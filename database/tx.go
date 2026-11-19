package database

import (
	"context"

	"gorm.io/gorm"
)

type txCtxKey struct{}

// WithTx 把事务会话绑进 context，供 repository 经 Ctx 取出。
func WithTx(ctx context.Context, tx *gorm.DB) context.Context {
	return context.WithValue(ctx, txCtxKey{}, tx)
}

// Ctx 取当前上下文会话：事务内返回 tx，否则返回主库。
func Ctx(ctx context.Context) *gorm.DB {
	if ctx != nil {
		if tx, ok := ctx.Value(txCtxKey{}).(*gorm.DB); ok && tx != nil {
			return tx.WithContext(ctx)
		}
	}
	return DB().WithContext(ctx)
}

// Transaction 在主库开事务，并把 tx 写入 context 交给 fn。
// 对齐业务层 @Transactional：同一 context 下的 repository.Ctx 读写都进同一事务。
func Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(WithTx(ctx, tx))
	})
}
