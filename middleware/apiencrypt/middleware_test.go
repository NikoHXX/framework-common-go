package apiencrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	m.Run()
}

func testConfig(t *testing.T) (APIEncryptConfig, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return APIEncryptConfig{
		Enabled:    true,
		PrivateKey: base64.StdEncoding.EncodeToString(privDER),
		PublicKey:  base64.StdEncoding.EncodeToString(pubDER),
	}, key
}

func seal(t *testing.T, pub *rsa.PublicKey, plain string) (header, body string) {
	t.Helper()
	aesPass, err := GenerateAESPassword()
	if err != nil {
		t.Fatal(err)
	}
	header, err = EncryptByRSA(EncryptByBase64(aesPass), pub)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := EncryptByAES(plain, aesPass)
	if err != nil {
		t.Fatal(err)
	}
	return header, strconv.Quote(cipher)
}

func openBody(t *testing.T, priv *rsa.PrivateKey, header, body string) string {
	t.Helper()
	decryptedHeader, err := DecryptByRSA(strings.TrimSpace(header), priv)
	if err != nil {
		t.Fatal(err)
	}
	aesPass, err := DecryptByBase64(decryptedHeader)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptByAES(strings.TrimSpace(body), aesPass)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func echoJSON(c *gin.Context) {
	b, _ := io.ReadAll(c.Request.Body)
	c.Data(http.StatusOK, "application/json", b)
}

func perform(r http.Handler, method, path, header, body, contentType string, extra http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if header != "" {
		req.Header.Set(DefaultAPIEncryptHeader, header)
	}
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func codeOf(t *testing.T, rec *httptest.ResponseRecorder) int {
	t.Helper()
	var got failBody
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是 JSON: %s", rec.Body.String())
	}
	return got.Code
}

func TestFilterDecryptsWhenHeaderPresentWithoutAnnotation(t *testing.T) {
	cfg, key := testConfig(t)
	r := gin.New()
	r.Use(Filter(cfg))
	r.POST("/open", echoJSON)

	header, body := seal(t, &key.PublicKey, `{"a":1}`)
	rec := perform(r, http.MethodPost, "/open", header, body, "application/json", nil)
	if rec.Body.String() != `{"a":1}` {
		t.Fatalf("明文 = %s", rec.Body.String())
	}
}

func TestFilterLeavesPlaintextWhenHeaderMissing(t *testing.T) {
	cfg, _ := testConfig(t)
	r := gin.New()
	r.Use(Filter(cfg))
	r.POST("/open", echoJSON)

	rec := perform(r, http.MethodPost, "/open", "", `{"a":1}`, "application/json", nil)
	if rec.Body.String() != `{"a":1}` {
		t.Fatalf("明文 = %s", rec.Body.String())
	}
}

func TestAnnotationRequiresHeader(t *testing.T) {
	cfg, key := testConfig(t)
	r := gin.New()
	r.Use(Filter(cfg))
	r.POST("/login", APIEncryptWithConfig(cfg), echoJSON)

	rec := perform(r, http.MethodPost, "/login", "", `{"a":1}`, "application/json", nil)
	if codeOf(t, rec) != 403 {
		t.Fatalf("code = %d body = %s", codeOf(t, rec), rec.Body.String())
	}

	header, body := seal(t, &key.PublicKey, `{"a":1}`)
	rec = perform(r, http.MethodPost, "/login", header, body, "application/json", nil)
	if rec.Body.String() != `{"a":1}` {
		t.Fatalf("解密后 = %s", rec.Body.String())
	}
}

func TestGlobalRequestRequiresHeaderExceptExcludes(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.GlobalRequest = true
	cfg.ExcludeRequestURLs = []string{"/**/importData"}
	r := gin.New()
	r.Use(Filter(cfg))
	r.POST("/user", echoJSON)
	r.PATCH("/user", echoJSON)
	r.POST("/user/importData", echoJSON)
	r.POST("/user/upload", echoJSON)
	r.GET("/user", echoJSON)

	rec := perform(r, http.MethodPost, "/user", "", `{}`, "application/json", nil)
	if codeOf(t, rec) != 403 {
		t.Fatalf("普通 POST code = %d", codeOf(t, rec))
	}
	rec = perform(r, http.MethodPatch, "/user", "", `{}`, "application/json", nil)
	if codeOf(t, rec) != 403 {
		t.Fatalf("PATCH code = %d body=%s", codeOf(t, rec), rec.Body.String())
	}
	rec = perform(r, http.MethodPost, "/user/importData", "", `{}`, "application/json", nil)
	if rec.Body.String() != `{}` {
		t.Fatalf("排除路径被拦截: %s", rec.Body.String())
	}
	rec = perform(r, http.MethodPost, "/user/upload", "", "file", "multipart/form-data; boundary=x", nil)
	if strings.Contains(rec.Body.String(), "没有访问权限") {
		t.Fatalf("multipart 被要求加密: %s", rec.Body.String())
	}
	rec = perform(r, http.MethodGet, "/user", "", "", "", nil)
	if strings.Contains(rec.Body.String(), "没有访问权限") {
		t.Fatalf("GET 被要求加密: %s", rec.Body.String())
	}
}

func TestGlobalResponseEncryptsJSONAndSkipsBinary(t *testing.T) {
	cfg, key := testConfig(t)
	cfg.GlobalResponse = true
	cfg.ExcludeResponseURLs = []string{"/**/export"}
	r := gin.New()
	r.Use(Filter(cfg))
	r.GET("/user", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.GET("/file", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/octet-stream", []byte("file-bytes"))
	})
	r.GET("/user/export", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.GET("/events", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/json", []byte(`{"ok":true}`))
	})

	rec := perform(r, http.MethodGet, "/user", "", "", "", nil)
	if rec.Header().Get(DefaultAPIEncryptHeader) == "" {
		t.Fatal("JSON 响应没有密钥头")
	}
	plain := openBody(t, key, rec.Header().Get(DefaultAPIEncryptHeader), rec.Body.String())
	if !strings.Contains(plain, `"ok":true`) {
		t.Fatalf("解密响应 = %s", plain)
	}

	rec = perform(r, http.MethodGet, "/file", "", "", "", nil)
	if rec.Header().Get(DefaultAPIEncryptHeader) != "" || rec.Body.String() != "file-bytes" {
		t.Fatalf("二进制被加密: header=%q body=%s", rec.Header().Get(DefaultAPIEncryptHeader), rec.Body.String())
	}
	rec = perform(r, http.MethodGet, "/user/export", "", "", "", nil)
	if rec.Header().Get(DefaultAPIEncryptHeader) != "" || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("排除路径的响应被加密: %s", rec.Body.String())
	}
	rec = perform(r, http.MethodGet, "/events", "", "", "", http.Header{"Accept": []string{"text/event-stream"}})
	if rec.Header().Get(DefaultAPIEncryptHeader) != "" {
		t.Fatal("SSE 响应被加密")
	}
}

func TestFullyExcludedSkipsHeader(t *testing.T) {
	cfg, key := testConfig(t)
	cfg.GlobalRequest = true
	cfg.GlobalResponse = true
	cfg.ExcludeURLs = []string{"/message"}
	r := gin.New()
	r.Use(Filter(cfg))
	r.POST("/message", echoJSON)

	header, body := seal(t, &key.PublicKey, `{"a":1}`)
	rec := perform(r, http.MethodPost, "/message", header, body, "application/json", nil)
	if rec.Body.String() != body {
		t.Fatalf("排除路径仍解密了请求: %s", rec.Body.String())
	}
	if rec.Header().Get(DefaultAPIEncryptHeader) != "" {
		t.Fatal("排除路径加密了响应")
	}
}

func TestAnnotationResponseEncryptWithoutGlobal(t *testing.T) {
	cfg, key := testConfig(t)
	r := gin.New()
	r.Use(Filter(cfg))
	r.POST("/secret", APIEncryptWithResponseWithConfig(cfg), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	header, body := seal(t, &key.PublicKey, `{"a":1}`)
	rec := perform(r, http.MethodPost, "/secret", header, body, "application/json", nil)
	if rec.Header().Get(DefaultAPIEncryptHeader) == "" {
		t.Fatalf("响应未加密: %s", rec.Body.String())
	}
	plain := openBody(t, key, rec.Header().Get(DefaultAPIEncryptHeader), rec.Body.String())
	if !strings.Contains(plain, `"ok":true`) {
		t.Fatalf("解密响应 = %s", plain)
	}
}
