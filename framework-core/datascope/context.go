// Package datascope 把数据权限计算要用的登录用户和当前接口权限码放进 request context。
// SQL 条件由业务模块按这些值拼，避免公共库依赖具体表。
package datascope

import (
	"context"

	"github.com/NikoHXX/framework-common-go/framework-core/model"
)

type ctxKey int

const (
	userKey ctxKey = iota
	permsKey
	ignoreKey
)

// WithLoginUser 挂上当前登录用户。未登录不要调用。
func WithLoginUser(ctx context.Context, user *model.LoginUser) context.Context {
	if user == nil {
		return ctx
	}
	return context.WithValue(ctx, userKey, user)
}

// LoginUser 取出当前登录用户。没有时返回 nil，调用方不加数据权限条件。
func LoginUser(ctx context.Context) *model.LoginUser {
	user, _ := ctx.Value(userKey).(*model.LoginUser)
	return user
}

// WithPerms 记录本接口校验通过的权限码，用于从 DataScopeRoleMap 里挑角色。
func WithPerms(ctx context.Context, perms []string) context.Context {
	if len(perms) == 0 {
		return ctx
	}
	cp := append([]string(nil), perms...)
	return context.WithValue(ctx, permsKey, cp)
}

// Perms 当前接口的权限码。空切片表示这条接口没有权限码约束，数据权限使用全部角色。
func Perms(ctx context.Context) []string {
	perms, _ := ctx.Value(permsKey).([]string)
	return perms
}

// Ignore 标记本次查询跳过数据权限，对齐 Java DataPermissionHelper.ignore。
func Ignore(ctx context.Context) context.Context {
	return context.WithValue(ctx, ignoreKey, true)
}

// Ignored 是否跳过数据权限。
func Ignored(ctx context.Context) bool {
	v, _ := ctx.Value(ignoreKey).(bool)
	return v
}
