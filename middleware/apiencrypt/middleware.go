// Package apiencrypt 接口加解密中间件，对齐 Java CryptoFilter。
//
// RSA 协商 AES 密钥、AES 加解密报文体。Filter 挂在引擎上：POST/PUT/PATCH 只要带密钥头就解密；
// globalRequest 时这些方法必须带密钥头；globalResponse 时加密 JSON/纯文本响应。
// 路由上的 APIEncryptWithConfig 等价于 @ApiEncrypt：全局请求加密关闭时，没带密钥头返回 403。
// APIEncryptWithResponseWithConfig 等价于 @ApiEncrypt(response=true)。
// !Enabled 时过滤器与路由中间件都直通。
//
// 自包含、不引 framework-core/middleware 与 framework-core/model/response：失败用 JSON 直写 {code,msg,data}，
// 不走全局 Recover 兜底。缺密钥头 403，解密/加密失败 500。HTTP 状态恒为 200。
package apiencrypt

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	defaultHeader  = "encrypt-key"    // 默认密钥头名
	defaultMaxBody = 10 * 1024 * 1024 // 默认密文上限 10MB
)

// Crypto 接口加解密器，持有解析后的密钥和排除规则。!Enabled 时为零值，过滤器与路由中间件都直通。
type Crypto struct {
	header          string
	priv            *rsa.PrivateKey
	pub             *rsa.PublicKey
	maxSize         int64
	globalRequest   bool
	globalResponse  bool
	excludeAll      []string
	excludeRequest  []string
	excludeResponse []string
}

// newCrypto 解析配置构造 Crypto。!Enabled 返回零值（中间件直通）；密钥解析失败 panic
// （启动期 fail-fast，与原 encrypt.Init 行为一致）。注册前就地铺默认值并校验，调用方无需手动校验。
func newCrypto(cfg APIEncryptConfig) *Crypto {
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		panic(fmt.Sprintf("apiEncrypt: %v", err))
	}
	if !cfg.Enabled {
		return &Crypto{}
	}
	priv, err := ParseRSAPrivateKey(cfg.PrivateKey)
	if err != nil {
		panic(fmt.Errorf("apiencrypt: 初始化失败: %w", err))
	}
	var pub *rsa.PublicKey
	if cfg.PublicKey != "" {
		pub, err = ParseRSAPublicKey(cfg.PublicKey)
		if err != nil {
			panic(fmt.Errorf("apiencrypt: 初始化失败: %w", err))
		}
	}
	header := cfg.HeaderFlag
	if header == "" {
		header = defaultHeader
	}
	return &Crypto{
		header:          header,
		priv:            priv,
		pub:             pub,
		maxSize:         defaultMaxBody,
		globalRequest:   cfg.GlobalRequest,
		globalResponse:  cfg.GlobalResponse,
		excludeAll:      cfg.ExcludeURLs,
		excludeRequest:  cfg.ExcludeRequestURLs,
		excludeResponse: cfg.ExcludeResponseURLs,
	}
}

// Filter 全局加解密，对齐 Java CryptoFilter。
// 挂在 RepeatableBody 之后、AccessLog / XSS 之前，这样日志和清洗拿到的是明文。
func Filter(cfg APIEncryptConfig) gin.HandlerFunc {
	e := newCrypto(cfg)
	return func(c *gin.Context) { e.filter(c) }
}

// APIEncryptWithConfig 等价于 @ApiEncrypt：要求解密请求体。全局过滤器已处理过的请求不再解密一次。
func APIEncryptWithConfig(cfg APIEncryptConfig) gin.HandlerFunc {
	e := newCrypto(cfg)
	return func(c *gin.Context) { e.run(c, false) }
}

// APIEncryptWithResponseWithConfig 等价于 @ApiEncrypt(response=true)。
func APIEncryptWithResponseWithConfig(cfg APIEncryptConfig) gin.HandlerFunc {
	e := newCrypto(cfg)
	return func(c *gin.Context) { e.run(c, true) }
}

// filter 执行全局规则：带密钥头就解密；globalRequest 缺头则 403；globalResponse 加密响应。
func (e *Crypto) filter(c *gin.Context) {
	if e.priv == nil || e.fullyExcluded(c) {
		c.Next()
		return
	}
	headerValue := strings.TrimSpace(c.GetHeader(e.header))
	if e.shouldDecrypt(c, headerValue) {
		if !e.decryptRequest(c, headerValue) {
			return
		}
		c.Set(ctxDecrypted, true)
	} else if e.requireGlobalRequest(c) {
		log.Printf("[apiencrypt] %s %s 要求加密传输但未携带 %s 头",
			c.Request.Method, c.Request.URL.Path, e.header)
		writeFail(c, 403, "没有访问权限，请联系管理员授权")
		return
	}
	if e.globalResponse && !e.skipResponse(c) {
		c.Set(ctxRespEnc, true)
		e.encryptResponse(c)
		return
	}
	c.Next()
}

// run 执行路由标记。全局过滤器已经解密或已经包住响应时，这里只补标记自己的那一半。
func (e *Crypto) run(c *gin.Context, withResponse bool) {
	if e.priv == nil {
		c.Next()
		return
	}
	// 排除路径和上传不要求加密。全局过滤器没装时，也要认这套规则。
	if !c.GetBool(ctxDecrypted) && isBodyMethod(c.Request.Method) && !e.skipRequest(c) {
		headerValue := strings.TrimSpace(c.GetHeader(e.header))
		if headerValue == "" {
			log.Printf("[apiencrypt] %s %s 要求加密传输但未携带 %s 头",
				c.Request.Method, c.Request.URL.Path, e.header)
			writeFail(c, 403, "没有访问权限，请联系管理员授权")
			return
		}
		if !e.decryptRequest(c, headerValue) {
			return
		}
	}
	if withResponse && !c.GetBool(ctxRespEnc) && !e.skipResponse(c) {
		e.encryptResponse(c)
		return
	}
	c.Next()
}

// decryptRequest 解密请求体并换回明文 body。
func (e *Crypto) decryptRequest(c *gin.Context, headerValue string) bool {
	if c.Request.ContentLength > e.maxSize {
		e.fail(c, "请求体超限")
		return false
	}
	if c.Request.Body == nil {
		e.fail(c, "请求体为空")
		return false
	}
	cipherBody, err := io.ReadAll(io.LimitReader(c.Request.Body, e.maxSize+1))
	if err != nil {
		e.fail(c, "读取请求体失败: "+err.Error())
		return false
	}
	if int64(len(cipherBody)) > e.maxSize {
		e.fail(c, "请求体超限")
		return false
	}
	// RSA 私钥解出 base64 编码的 AES 密钥。
	decryptedHeader, err := DecryptByRSA(headerValue, e.priv)
	if err != nil {
		e.fail(c, "RSA 解密 AES 秘钥失败: "+err.Error())
		return false
	}
	// 再 base64 解一次才是真正的 AES 密钥。
	aesPassword, err := DecryptByBase64(decryptedHeader)
	if err != nil {
		e.fail(c, "AES 秘钥 base64 解码失败: "+err.Error())
		return false
	}
	// AES 解密请求体。
	plain, err := DecryptByAES(unwrapJSONString(bytes.TrimSpace(cipherBody)), aesPassword)
	if err != nil {
		e.fail(c, "AES 解密请求体失败: "+err.Error())
		return false
	}
	body := []byte(plain)
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	c.Request.ContentLength = int64(len(body))
	c.Request.Header.Set("Content-Type", "application/json")
	// 同步更新 BodyBytesKey：RepeatableBody 在本中间件之前已缓存密文，此处覆盖为明文，
	// 让下游 c.Get(gin.BodyBytesKey) 取到的是明文。
	c.Set(gin.BodyBytesKey, body)
	return true
}

// encryptResponse 缓冲响应体。JSON / 纯文本才加密，下载和空响应原样写出。
func (e *Crypto) encryptResponse(c *gin.Context) {
	if e.pub == nil {
		log.Printf("[apiencrypt] %s 配置了响应加密但未提供公钥", c.Request.URL.Path)
		writeFail(c, 500, "响应加密失败")
		return
	}
	aesPassword, err := GenerateAESPassword()
	if err != nil {
		e.failResponse(c, "生成 AES 秘钥失败: "+err.Error())
		return
	}
	encryptedKey, err := EncryptByRSA(EncryptByBase64(aesPassword), e.pub)
	if err != nil {
		e.failResponse(c, "RSA 加密 AES 秘钥失败: "+err.Error())
		return
	}

	original := c.Writer
	buf := &cryptoWriter{ResponseWriter: original}
	c.Writer = buf
	c.Next()
	// 还原 c.Writer，否则 Recover 在本函数返回后渲染错误会落进已用完的缓冲区。
	c.Writer = original

	if buf.body.Len() == 0 {
		buf.commit(nil)
		return
	}
	plain := buf.body.String()
	if !shouldEncryptResponseBody(original.Header().Get("Content-Type"), plain) {
		buf.commit(buf.body.Bytes())
		return
	}
	cipherText, err := EncryptByAES(plain, aesPassword)
	if err != nil {
		// 加密失败绝不能退回写明文，丢弃响应体并回错误。
		log.Printf("[apiencrypt] %s 响应加密失败,已丢弃响应体: %v", c.Request.URL.Path, err)
		buf.discardAndFail(e.header)
		return
	}
	h := original.Header()
	h.Set(e.header, encryptedKey)
	h.Add("Access-Control-Expose-Headers", e.header)
	h.Set("Content-Type", "text/plain;charset=utf-8")
	buf.commit([]byte(cipherText))
}

// shouldEncryptResponseBody 只加密 JSON 和纯文本。未标 Content-Type 时看正文是否像 JSON。
func shouldEncryptResponseBody(contentType, body string) bool {
	if strings.TrimSpace(body) == "" {
		return false
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "text/event-stream") {
		return false
	}
	if ct == "" {
		trimmed := strings.TrimSpace(body)
		return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
	}
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "text/plain")
}

// unwrapJSONString 剥掉密文外层的 JSON 字符串引号。
//
// 前端 axios 把加密后的 base64 串当 JSON body 发（Content-Type 是 application/json），
// transformRequest 会 JSON.stringify 一次，于是上线的 body 是 "abc123=="——带引号。
// 原实现用 hutool 的 base64 解码器会静默跳过非字母表字符（引号被忽略），
// 而 Go 标准库 base64 严格报错(illegal base64 data at input byte 0)，故须显式剥离。
func unwrapJSONString(b []byte) string {
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		return string(b[1 : len(b)-1])
	}
	return string(b)
}

// failBody 失败响应体，形态同 framework-core/model/response.R（Data 恒为 null）。
// 用结构体而非 fmt 拼串：msg 含引号时拼串会产出非法 JSON。
type failBody struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

// writeFail 直写失败 JSON 并终止链：HTTP 恒 200，body code/msg 由参数给。
// 不引 framework-core/model/response，与本包自包含的约定一致。
func writeFail(c *gin.Context, code int, msg string) {
	c.AbortWithStatusJSON(http.StatusOK, failBody{Code: code, Msg: msg})
}

// fail 记录明细并回请求解密失败的统一文案。响应码与原 errs.New(0,...) 经 Recover 回落 500 一致。
func (e *Crypto) fail(c *gin.Context, detail string) {
	log.Printf("[apiencrypt] %s %s 解密失败: %s", c.Request.Method, c.Request.URL.Path, detail)
	writeFail(c, 500, "请求解密失败")
}

// failResponse 响应加密前置步骤失败时回错误，此时 handler 还没执行。
func (e *Crypto) failResponse(c *gin.Context, detail string) {
	log.Printf("[apiencrypt] %s 响应加密准备失败: %s", c.Request.URL.Path, detail)
	writeFail(c, 500, "响应加密失败")
}

// cryptoWriter 把状态码和正文都留到最后再写，便于按 Content-Type 决定加密还是原样返回。
type cryptoWriter struct {
	gin.ResponseWriter
	body        bytes.Buffer
	status      int
	wroteHeader bool
}

func (w *cryptoWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.status = code
	w.wroteHeader = true
}

func (w *cryptoWriter) WriteHeaderNow() {}

func (w *cryptoWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(b)
}

func (w *cryptoWriter) WriteString(s string) (int, error) { return w.Write([]byte(s)) }

func (w *cryptoWriter) Flush() {}

func (w *cryptoWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *cryptoWriter) Size() int { return w.body.Len() }

func (w *cryptoWriter) Written() bool { return w.wroteHeader || w.body.Len() > 0 }

// commit 把缓冲的状态码和正文写进真正的响应。body 为 nil 时只补状态码。
func (w *cryptoWriter) commit(body []byte) {
	if !w.wroteHeader && len(body) == 0 {
		return
	}
	code := w.status
	if code == 0 {
		code = http.StatusOK
	}
	if body != nil {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}
	w.ResponseWriter.WriteHeader(code)
	if len(body) > 0 {
		_, _ = w.ResponseWriter.Write(body)
	}
}

// discardAndFail 丢弃已缓冲的明文并写一个加密失败的响应。
func (w *cryptoWriter) discardAndFail(header string) {
	w.body.Reset()
	h := w.Header()
	h.Del(header) // 密钥头必须撤掉：响应体已不是用它加密的
	h.Set("Content-Type", "application/json; charset=utf-8")
	body, _ := json.Marshal(failBody{Code: 500, Msg: "响应加密失败"})
	w.wroteHeader = true
	w.status = http.StatusOK
	w.commit(body)
}
