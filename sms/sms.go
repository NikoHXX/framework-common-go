// Package sms 大厂商短信发送工具（对齐 sms4j 请求契约）。
//
// 职责仅限「凭据 + 模板码 → 调厂商网关」；模板缓存、默认厂商、发送记录由业务层负责。
// 已对接：alibaba / tencent / yunpian / huawei；下拉与 NewSender 共用同一枚举表。
package sms

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrUnsupportedSupplier 厂商未实现或名称未知。
var ErrUnsupportedSupplier = errors.New("sms: 暂不支持该短信厂商")

// Credentials 厂商凭据，字段对齐 sys_sms_config / sms4j BaseConfig(+华为扩展)。
//
// 当前发信实现仅大厂商：alibaba / tencent / yunpian / huawei。
type Credentials struct {
	AccessKeyID     string // 阿里 AccessKeyId / 腾讯 SecretId / 云片 apikey / 华为 APP_Key
	AccessKeySecret string // 对应秘钥；云片可空
	Signature       string // 短信签名（华为侧多为签名名称，通道号用 Sender）
	SdkAppID        string // 腾讯 SmsSdkAppId 等
	Sender          string // 华为国内短信签名通道号
	URL             string // 华为 APP 接入地址；其它厂商也可作自定义 endpoint
	StatusCallBack  string // 华为短信状态报告接收地址
	RegionID        string // 可选地域，空则用厂商默认（腾讯等）
}

// SendRequest 单次发送入参。
type SendRequest struct {
	Phone        string
	TemplateCode string            // 厂商侧模板 ID
	Params       map[string]string // 具名模板变量（阿里/云片等）
	// ParamValues 有序模板参数（腾讯等要求数组）。
	// 为空时按 Params 的 key 字典序取值。
	ParamValues []string
}

// SendResult 网关调用结果。
type SendResult struct {
	Success  bool
	Message  string // 失败时的可读原因（可直接给前端）
	Response any    // 原始响应，便于落库
}

// Sender 短信发送器。
type Sender interface {
	Send(ctx context.Context, req SendRequest) (SendResult, error)
}

// NewSender 按厂商 code 构造 Sender；未知或未实现返回 ErrUnsupportedSupplier。
func NewSender(supplier string, cred Credentials) (Sender, error) {
	supplier = strings.ToLower(strings.TrimSpace(supplier))
	if supplier == "" {
		return nil, fmt.Errorf("%w: 厂商为空", ErrUnsupportedSupplier)
	}
	switch supplier {
	case SupplierAlibaba:
		return newAlibabaSender(cred)
	case SupplierTencent:
		return newTencentSender(cred)
	case SupplierYunpian:
		return newYunpianSender(cred)
	case SupplierHuawei:
		return newHuaweiSender(cred)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedSupplier, supplier)
	}
}

// SupportedSuppliers 已对接厂商 code（与 SupplierSelectList 同源）。
func SupportedSuppliers() []string {
	list := SupplierSelectList()
	out := make([]string, 0, len(list))
	for _, o := range list {
		out = append(out, o.Value)
	}
	return out
}

// IsSupported 是否已对接发信。
func IsSupported(supplier string) bool {
	supplier = strings.ToLower(strings.TrimSpace(supplier))
	for _, s := range SupportedSuppliers() {
		if s == supplier {
			return true
		}
	}
	return false
}
