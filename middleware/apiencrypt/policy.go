package apiencrypt

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/NikoHXX/framework-common-go/middleware/xss"
)

const (
	// ctxDecrypted 全局过滤器已经把请求体换成明文。
	ctxDecrypted = "apiencrypt.decrypted"
	// ctxRespEnc 全局过滤器已经包住响应，路由中间件不要再包一层。
	ctxRespEnc = "apiencrypt.response"
)

// isBodyMethod POST/PUT/PATCH 才有请求体，与 Java ApiDecryptSupport.isBodyRequest 一致。
func isBodyMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func requestPath(c *gin.Context) string {
	if c.Request == nil || c.Request.URL == nil {
		return ""
	}
	return c.Request.URL.Path
}

// fullyExcluded 命中 excludeUrls：请求和响应都不处理。
func (e *Crypto) fullyExcluded(c *gin.Context) bool {
	return xss.MatchAnyPath(requestPath(c), e.excludeAll)
}

// skipRequest 跳过请求体加解密：整段排除、excludeRequestUrls，或 multipart 上传。
func (e *Crypto) skipRequest(c *gin.Context) bool {
	if e.fullyExcluded(c) || xss.MatchAnyPath(requestPath(c), e.excludeRequest) {
		return true
	}
	ct := c.GetHeader("Content-Type")
	return strings.HasPrefix(strings.ToLower(ct), "multipart/form-data")
}

// skipResponse 跳过响应加密：整段排除、excludeResponseUrls，或 SSE。
func (e *Crypto) skipResponse(c *gin.Context) bool {
	if e.fullyExcluded(c) || xss.MatchAnyPath(requestPath(c), e.excludeResponse) {
		return true
	}
	accept := c.GetHeader("Accept")
	return strings.Contains(strings.ToLower(accept), "text/event-stream")
}

// shouldDecrypt 携带密钥头的 POST/PUT/PATCH 都解密，不要求路由上有加密标记。
func (e *Crypto) shouldDecrypt(c *gin.Context, header string) bool {
	if e.skipRequest(c) || !isBodyMethod(c.Request.Method) {
		return false
	}
	return header != ""
}

// requireGlobalRequest 全局请求加密开启时，带请求体的接口必须有密钥头。
func (e *Crypto) requireGlobalRequest(c *gin.Context) bool {
	return e.globalRequest && !e.skipRequest(c) && isBodyMethod(c.Request.Method)
}
