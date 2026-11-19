// Package loginhelper 登录鉴权助手
package loginhelper

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	sasession "github.com/NikoHXX/sa-token-go/core/session"
	sagin "github.com/NikoHXX/sa-token-go/integrations/gin"
	"github.com/NikoHXX/sa-token-go/stputil"
	"github.com/gin-gonic/gin"

	"github.com/NikoHXX/framework-common-go/framework-core/constant"
	"github.com/NikoHXX/framework-common-go/framework-core/enum"
	authmodel "github.com/NikoHXX/framework-common-go/framework-core/model"
	"github.com/NikoHXX/framework-common-go/ip"
	"github.com/NikoHXX/framework-common-go/middleware/xss"
)

// LoginUserKey token session 中 *LoginUser 的键。
const LoginUserKey = "loginUser"

// TokenExtraKey token session 中 Extra 快照的键（对齐 Java SaLoginParameter.setExtra）。
const TokenExtraKey = "tokenExtra"

// Extra 键名，对齐 Java LoginHelper。
const (
	UserKey               = "userId"
	UserNameKey           = "userName"
	DeptKey               = "deptId"
	DeptNameKey           = "deptName"
	ClientKey             = "clientid"
	ClientAccessPathKey   = "clientAccessPath"
	ClientIPWhitelistKey  = "clientIpWhitelist"
)

// LoginOptions 单次登录的超时覆盖项，对应 sys_client 的 timeout / active_timeout 两列。
//
// 零值表示该项不覆盖、沿用 satoken 全局配置。需 satoken.dynamicActiveTimeout=true
// 才会生效，否则 sa-token-go 会丢弃 ActiveTimeout 并打告警。
type LoginOptions struct {
	// Device 设备类型，对应 SaLoginParameter.deviceType，"" 走默认。
	Device string
	// Timeout token 固定有效期(秒)，0 表示沿用全局配置。
	Timeout int64
	// ActiveTimeout token 最低活跃频率(秒)，0 表示沿用全局配置。
	ActiveTimeout int64
	// IsConcurrent 本次是否允许同账号并发登录；nil 沿用全局 satoken.isConcurrent。
	IsConcurrent *bool
	// Extra 写入 token session 的附加字段（clientid / 路径 / IP 白名单 / userId 等）。
	Extra map[string]string
}

// Login 签发令牌、把 *LoginUser 存入 token session，并回填 loginUser.Token。
// device 对应 SaLoginParameter.deviceType，"" 走默认。
func Login(loginUser *authmodel.LoginUser, device string) (string, error) {
	return LoginWithOptions(loginUser, LoginOptions{Device: device})
}

// LoginWithOptions 按客户端超时签发令牌，其余同 Login。
//
// JAVA 的超时是按 sys_client 配的，各客户端(pc / app / 小程序)可不同，
// 故须随每次登录传入而非只读全局配置。
func LoginWithOptions(loginUser *authmodel.LoginUser, opts LoginOptions) (string, error) {
	loginID, err := loginUser.LoginID()
	if err != nil {
		return "", err
	}

	param := sagin.NewLoginParameter()
	param.Device = opts.Device
	param.Timeout = opts.Timeout
	if opts.ActiveTimeout != 0 {
		param.SetActiveTimeout(opts.ActiveTimeout)
	}
	if opts.IsConcurrent != nil {
		param.SetIsConcurrent(*opts.IsConcurrent)
	}

	token, err := sagin.LoginWithParameter(loginID, param)
	if err != nil {
		return "", err
	}
	loginUser.Token = token

	sess, err := stputil.GetTokenSessionOrCreate(token)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(loginUser)
	if err != nil {
		return "", err
	}
	// 必须显式带 TTL：session.Set 省略 TTL 时会以「无过期」落库，
	// 令 token 过期后这份 LoginUser 仍长留 Redis。
	if err := setWithTokenTTL(sess, token, LoginUserKey, string(payload)); err != nil {
		return "", err
	}
	if err := writeTokenExtra(sess, token, mergeLoginExtra(loginUser, opts.Extra)); err != nil {
		return "", err
	}
	if err := stputil.SetPermissions(loginID, toSaTokenPerms(loginUser.MenuPermission)); err != nil {
		return "", err
	}
	if err := stputil.SetRoles(loginID, loginUser.RolePermission); err != nil {
		return "", err
	}
	return token, nil
}

// mergeLoginExtra 合并调用方 Extra，并补齐 Java LoginHelper.login 写入的用户快照键。
func mergeLoginExtra(loginUser *authmodel.LoginUser, extra map[string]string) map[string]string {
	out := make(map[string]string, len(extra)+4)
	for k, v := range extra {
		out[k] = v
	}
	if loginUser == nil {
		return out
	}
	out[UserKey] = strconv.FormatInt(loginUser.UserID, 10)
	out[UserNameKey] = loginUser.Username
	out[DeptKey] = strconv.FormatInt(loginUser.DeptID, 10)
	out[DeptNameKey] = loginUser.DeptName
	return out
}

func writeTokenExtra(sess *sasession.Session, token string, extra map[string]string) error {
	if len(extra) == 0 {
		return nil
	}
	payload, err := json.Marshal(extra)
	if err != nil {
		return err
	}
	return setWithTokenTTL(sess, token, TokenExtraKey, string(payload))
}

// GetExtra 取当前请求 token 的 Extra 字段，未登录或缺键返回 ""。
func GetExtra(c *gin.Context, key string) string {
	return GetExtraByToken(sagin.GetTokenFromCtx(c), key)
}

// GetExtraByToken 按 token 读取 Extra，对齐 Java StpUtil.getExtra。
func GetExtraByToken(token, key string) string {
	if token == "" || key == "" {
		return ""
	}
	// satoken 未初始化时 GetTokenSession 会 panic，校验侧当 Extra 为空处理。
	defer func() { _ = recover() }()
	sess, err := sagin.GetTokenSession(token)
	if err != nil || sess == nil {
		return ""
	}
	raw := sess.GetString(TokenExtraKey)
	if raw == "" {
		return ""
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return ""
	}
	return m[key]
}

// ValidateClientBinding 校验请求 clientid 与 token Extra 绑定，并校验路径/IP 白名单。
// 对齐 Java AuthFilter；失败返回中文提示文案。
func ValidateClientBinding(r *http.Request, token string) (msg string, ok bool) {
	if r == nil {
		return "", true
	}
	headerCid := strings.TrimSpace(r.Header.Get(ClientKey))
	paramCid := strings.TrimSpace(r.URL.Query().Get(ClientKey))
	extraCid := GetExtraByToken(token, ClientKey)
	if extraCid != headerCid && extraCid != paramCid {
		return "客户端ID与Token不匹配", false
	}

	accessPath := GetExtraByToken(token, ClientAccessPathKey)
	if accessPath != "" {
		rules := splitClientRules(accessPath)
		for i, rule := range rules {
			rules[i] = normalizeAccessPath(rule)
		}
		reqPath := r.URL.Path
		if !xss.MatchAnyPath(reqPath, rules) {
			return "当前客户端未授权访问该接口路径", false
		}
	}

	ipWhitelist := GetExtraByToken(token, ClientIPWhitelistKey)
	if ipWhitelist != "" {
		clientIP := ip.ResolveClientIP(r)
		matched := false
		for _, rule := range splitClientRules(ipWhitelist) {
			if ip.MatchRule(rule, clientIP) {
				matched = true
				break
			}
		}
		if !matched {
			return "当前客户端IP不在白名单内", false
		}
	}
	return "", true
}

func splitClientRules(s string) []string {
	if s == "" {
		return nil
	}
	// 对齐 Java CLIENT_RULE_SEPARATOR_REGEX = [,;\r\n]+
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == '\r' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func normalizeAccessPath(path string) string {
	if path == "*" || path == "/**" {
		return "/**"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

// setWithTokenTTL 以 token 的剩余有效期为 TTL 写 session，使两者同步失效。
// token 被配成永不过期(TTL=-1)时不带 TTL，与 token 行为保持一致。
func setWithTokenTTL(sess *sasession.Session, token, key, value string) error {
	ttl, err := sagin.GetManager().GetTokenTimeout(token)
	if err != nil {
		return err
	}
	if ttl > 0 {
		return sess.Set(key, value, time.Duration(ttl)*time.Second)
	}
	return sess.Set(key, value)
}

// toSaTokenPerms 把超管的 *:*:* 换成 sa-token 认得的 *，其余原样。
func toSaTokenPerms(perms []string) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		if p == constant.AllPermission {
			p = "*"
		}
		out = append(out, p)
	}
	return out
}

// loginUserCacheKey gin.Context 中本请求登录用户快照的键。
const loginUserCacheKey = "framework:loginUser"

// GetLoginUser 取当前请求的登录用户，未登录返回 nil。
func GetLoginUser(c *gin.Context) *authmodel.LoginUser {
	if v, ok := c.Get(loginUserCacheKey); ok {
		// 未登录时存的是 nil，断言失败正好落回 nil。
		lu, _ := v.(*authmodel.LoginUser)
		return lu
	}
	lu := GetLoginUserByToken(sagin.GetTokenFromCtx(c))
	c.Set(loginUserCacheKey, lu)
	return lu
}

// GetLoginUserByToken 按指定 token 取登录用户。
func GetLoginUserByToken(token string) *authmodel.LoginUser {
	if token == "" {
		return nil
	}
	sess, err := sagin.GetTokenSession(token)
	if err != nil || sess == nil {
		return nil
	}
	v := sess.GetString(LoginUserKey)
	if v == "" {
		return nil
	}
	var lu authmodel.LoginUser
	if err := json.Unmarshal([]byte(v), &lu); err != nil {
		return nil
	}
	return &lu
}

// GetLoginID 取当前 token 的 loginID（形如 "sys_user-123"），未登录返回 ""。
func GetLoginID(c *gin.Context) string {
	token := sagin.GetTokenFromCtx(c)
	if token == "" {
		return ""
	}
	id, err := sagin.GetLoginID(token)
	if err != nil {
		return ""
	}
	return id
}

// GetUserID 取当前登录用户 ID，未登录返回 0。
func GetUserID(c *gin.Context) int64 {
	if lu := GetLoginUser(c); lu != nil {
		return lu.UserID
	}
	return 0
}

// GetUserIDStr 取当前登录用户 ID 字符串，未登录返回 ""。
func GetUserIDStr(c *gin.Context) string {
	if id := GetUserID(c); id != 0 {
		return strconv.FormatInt(id, 10)
	}
	return ""
}

// GetUsername 取当前登录用户名，未登录返回 ""。
func GetUsername(c *gin.Context) string {
	if lu := GetLoginUser(c); lu != nil {
		return lu.Username
	}
	return ""
}

// GetDeptID 取当前登录用户部门 ID，未登录返回 0。
func GetDeptID(c *gin.Context) int64 {
	if lu := GetLoginUser(c); lu != nil {
		return lu.DeptID
	}
	return 0
}

// GetDeptName 取当前登录用户部门名，未登录返回 ""。
func GetDeptName(c *gin.Context) string {
	if lu := GetLoginUser(c); lu != nil {
		return lu.DeptName
	}
	return ""
}

// GetUserType 取当前登录用户类型，未登录返回 ""。
func GetUserType(c *gin.Context) string {
	if lu := GetLoginUser(c); lu != nil {
		return lu.UserType
	}
	return ""
}

// IsSuperAdmin 判断指定用户 ID 是否超级管理员。
func IsSuperAdmin(userID int64) bool {
	return userID == constant.SuperAdminUserID
}

// IsCurrentSuperAdmin 判断当前登录用户是否超级管理员。
func IsCurrentSuperAdmin(c *gin.Context) bool {
	return IsSuperAdmin(GetUserID(c))
}

// IsLogin 判断当前请求是否携带有效登录态。
func IsLogin(c *gin.Context) bool {
	token := sagin.GetTokenFromCtx(c)
	return token != "" && sagin.IsLogin(token)
}

// LogoutUser 注销指定后台用户(sys_user)的会话。
func LogoutUser(userID int64) {
	LogoutUserOfType(enum.UserTypeSys.Code, userID)
}

// LogoutUserOfType 按用户类型注销会话，对齐 Java 按 loginId(userType-userId) 踢下线。
func LogoutUserOfType(userType string, userID int64) {
	if userID <= 0 {
		return
	}
	if userType == "" {
		userType = enum.UserTypeSys.Code
	}
	loginID := userType + authmodel.LoginIDSeparator + strconv.FormatInt(userID, 10)
	if err := sagin.Logout(loginID); err != nil {
		log.Printf("[satoken] 注销用户 %s 会话失败: %v", loginID, err)
	}
}

// LogoutUsers 批量注销后台用户会话，逐个调用 LogoutUser。
// 不做去重：sys_user_role 不会给同一用户重复行，调用方传入的集合语义上也无重复预期。
func LogoutUsers(userIDs []int64) {
	for _, id := range userIDs {
		LogoutUser(id)
	}
}

// LogoutUsersOfType 按用户类型批量注销会话。
func LogoutUsersOfType(userType string, userIDs []int64) {
	for _, id := range userIDs {
		LogoutUserOfType(userType, id)
	}
}
