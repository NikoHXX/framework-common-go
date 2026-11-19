package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	xoauth2 "golang.org/x/oauth2"
)

func stubOAuthConfig(cfg ProviderConfig, scopes []string) *xoauth2.Config {
	return &xoauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
		Scopes:       scopes,
		Endpoint:     xoauth2.Endpoint{AuthURL: "https://invalid.local/auth", TokenURL: "https://invalid.local/token"},
	}
}

func doJSON(ctx context.Context, client *http.Client, method, endpoint string,
	header http.Header, body any, dest any) error {

	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("oauth2: 序列化请求失败: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return fmt.Errorf("oauth2: 构造请求失败: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	req.Header.Set("Accept", "application/json")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("oauth2: 请求 %s 失败: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("oauth2: 读取响应失败: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("oauth2: %s 返回 %d: %s", endpoint, resp.StatusCode, truncate(string(raw), 200))
	}
	if dest == nil {
		return nil
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return fmt.Errorf("oauth2: 解析响应失败: %w, 响应: %s", err, truncate(string(raw), 200))
	}
	return nil
}

func doFormGET(ctx context.Context, client *http.Client, endpoint string, q url.Values, dest any) error {
	u := endpoint
	if len(q) > 0 {
		u = endpoint + "?" + q.Encode()
	}
	return getJSON(ctx, client, u, nil, dest)
}

func tokenWithExpiry(access, refresh string, expiresIn int, extra map[string]any) *xoauth2.Token {
	tok := &xoauth2.Token{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
	}
	if expiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	if len(extra) > 0 {
		tok = tok.WithExtra(extra)
	}
	return tok
}

func joinScopes(scopes []string, sep string) string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, sep)
}

func doGETRaw(ctx context.Context, client *http.Client, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("oauth2: 构造请求失败: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth2: 请求 %s 失败: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("oauth2: 读取响应失败: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("oauth2: %s 返回 %d: %s", endpoint, resp.StatusCode, truncate(string(raw), 200))
	}
	return string(raw), nil
}

// parseQueryOrJSON 解析 QQ token 等「表单串或 JSON」响应，对齐 JustAuth parseStringToMap。
func parseQueryOrJSON(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	out := map[string]string{}
	if raw == "" {
		return out
	}
	if strings.HasPrefix(raw, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err == nil {
			for k, v := range obj {
				out[k] = fmt.Sprint(v)
			}
			return out
		}
	}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return out
	}
	for k, vs := range vals {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}
