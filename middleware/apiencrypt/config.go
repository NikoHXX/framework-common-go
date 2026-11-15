package apiencrypt

import "fmt"

// DefaultAPIEncryptHeader 传递 AES 密钥的头名。
const DefaultAPIEncryptHeader = "encrypt-key"

// APIEncryptConfig 接口加解密配置，对齐 Java api-decrypt。
type APIEncryptConfig struct {
	// Enabled 是否启用。false 时过滤器与路由中间件都直通。
	Enabled bool `mapstructure:"enabled"`
	// GlobalRequest 为 true 时，POST/PUT/PATCH 必须带密钥头。开启后不再看路由标记。
	GlobalRequest bool `mapstructure:"globalRequest"`
	// GlobalResponse 为 true 时加密全部响应（排除路径、SSE、非 JSON 除外）。开启后不再看路由标记。
	GlobalResponse bool `mapstructure:"globalResponse"`
	// HeaderFlag 传递 AES 密钥的请求/响应头名，为空表示用 DefaultAPIEncryptHeader。
	HeaderFlag string `mapstructure:"headerFlag"`
	// PublicKey 响应加密用的 RSA 公钥，base64 编码的 X.509 SPKI。
	PublicKey string `mapstructure:"publicKey"`
	// PrivateKey 请求解密用的 RSA 私钥，base64 编码的 PKCS#8。
	PrivateKey string `mapstructure:"privateKey"`
	// ExcludeURLs 请求与响应都不参与加解密，Ant 风格。
	ExcludeURLs []string `mapstructure:"excludeUrls"`
	// ExcludeRequestURLs 只跳过请求体加解密，响应仍可加密。
	ExcludeRequestURLs []string `mapstructure:"excludeRequestUrls"`
	// ExcludeResponseURLs 只跳过响应加解密。
	ExcludeResponseURLs []string `mapstructure:"excludeResponseUrls"`
}

// applyDefaults 就地铺兜底默认值。HeaderFlag 为空补默认头名；其余字段无默认。
func (a *APIEncryptConfig) applyDefaults() {
	if a.HeaderFlag == "" {
		a.HeaderFlag = DefaultAPIEncryptHeader
	}
}

// validate 校验配置合理性，注册期调用，不合规直接 panic。!Enabled 时直通，不要求密钥。
func (a APIEncryptConfig) validate() error {
	if !a.Enabled {
		return nil
	}
	if a.PrivateKey == "" {
		return fmt.Errorf("apiEncrypt.privateKey 未配置")
	}
	if a.GlobalResponse && a.PublicKey == "" {
		return fmt.Errorf("apiEncrypt.publicKey 未配置")
	}
	return nil
}
