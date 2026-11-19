package xss

import (
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

// htmlMarkRE 对齐 Hutool HtmlUtil.RE_HTML_MARK：含 HTML 标签即视为脚本字符。
var htmlMarkRE = regexp.MustCompile(`(?i)<[^>]+>`)

var registerOnce sync.Once

// ContainsHTML 字符串是否含 HTML 标签，对齐 Java XssValidator。
func ContainsHTML(s string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	return htmlMarkRE.MatchString(s)
}

// RegisterGinBinding 注册 binding 标签 `noxss`：字段不得含 HTML 标签。
// 幂等；在应用启动期调用一次即可（import 本包后手动调，或走 EnsureGinBinding）。
func RegisterGinBinding() {
	registerOnce.Do(func() {
		engine, ok := binding.Validator.Engine().(*validator.Validate)
		if !ok {
			return
		}
		_ = engine.RegisterValidation("noxss", func(fl validator.FieldLevel) bool {
			switch fl.Field().Kind() {
			case reflect.String:
				return !ContainsHTML(fl.Field().String())
			default:
				return true
			}
		})
	})
}

// EnsureGinBinding 供业务 init / main 调用，保证 noxss 已注册。
func EnsureGinBinding() { RegisterGinBinding() }
