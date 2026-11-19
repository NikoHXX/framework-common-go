// Package sensitive 响应字段脱敏，对齐 Java common-sensitive。
package sensitive

import (
	"strings"
	"unicode/utf8"

	"github.com/NikoHXX/framework-common-go/framework-core/constant"
	"github.com/NikoHXX/framework-common-go/framework-core/model"
)

// ShouldMask 是否应对当前用户打码。
// 对齐 Java SysSensitiveServiceImpl：未登录打码；有任一权限或超管则不打码。
func ShouldMask(user *model.LoginUser, perms ...string) bool {
	if user == nil {
		return true
	}
	if user.UserID == constant.SuperAdminUserID {
		return false
	}
	if len(perms) == 0 {
		return true
	}
	permSet := make(map[string]struct{}, len(user.MenuPermission))
	for _, p := range user.MenuPermission {
		if p == constant.AllPermission || p == "*" {
			return false
		}
		permSet[p] = struct{}{}
	}
	for _, need := range perms {
		if _, ok := permSet[need]; ok {
			return false
		}
	}
	return true
}

// Phone 手机号脱敏，对齐 Hutool DesensitizedUtil.mobilePhone：138****8000。
func Phone(s string) string {
	s = strings.TrimSpace(s)
	n := len(s)
	if n < 7 {
		return s
	}
	return s[:3] + "****" + s[n-4:]
}

// Email 邮箱脱敏，对齐 Hutool DesensitizedUtil.email：a****@example.com。
func Email(s string) string {
	s = strings.TrimSpace(s)
	at := strings.IndexByte(s, '@')
	if at <= 0 {
		return s
	}
	local := s[:at]
	domain := s[at:]
	r, size := utf8.DecodeRuneInString(local)
	if r == utf8.RuneError && size == 1 {
		return s
	}
	return string(r) + "****" + domain
}
