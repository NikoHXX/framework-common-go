package sms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 对齐 sms4j：url 为 APP 接入地址基址，再拼 HUAWEI_REQUEST_URL。
const (
	huaweiDefaultBase = "https://smsapi.cn-north-4.myhuaweicloud.com:443"
	huaweiRequestPath = "/sms/batchSendSms/v1"
)

type huaweiSender struct {
	appKey         string
	appSecret      string
	sender         string // 通道号 SysSmsConfig.sender
	signature      string // 签名名称 SysSmsConfig.signature（部分模板需要）
	statusCallBack string
	apiURL         string
	http           *http.Client
}

func newHuaweiSender(cred Credentials) (Sender, error) {
	if cred.AccessKeyID == "" || cred.AccessKeySecret == "" {
		return nil, fmt.Errorf("sms: 华为 APP_Key/APP_Secret 未配置")
	}
	if cred.Sender == "" {
		return nil, fmt.Errorf("sms: 华为通道号未配置（填入 sender）")
	}
	apiURL := resolveHuaweiAPIURL(cred.URL)
	return &huaweiSender{
		appKey:         cred.AccessKeyID,
		appSecret:      cred.AccessKeySecret,
		sender:         cred.Sender,
		signature:      cred.Signature,
		statusCallBack: cred.StatusCallBack,
		apiURL:         apiURL,
		http:           &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (s *huaweiSender) Send(ctx context.Context, req SendRequest) (SendResult, error) {
	if req.Phone == "" || req.TemplateCode == "" {
		return SendResult{Success: false, Message: "手机号或模板码为空"}, fmt.Errorf("sms: 手机号或模板码为空")
	}
	templateParas, _ := json.Marshal(orderedParamValues(req))
	body := map[string]any{
		"from":          s.sender,
		"to":            req.Phone,
		"templateId":    req.TemplateCode,
		"templateParas": string(templateParas),
	}
	if s.statusCallBack != "" {
		body["statusCallback"] = s.statusCallBack
	}
	// 华为部分签名场景需要附带 signature；与 sms4j 一致有则带。
	if s.signature != "" {
		body["signature"] = s.signature
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return SendResult{Success: false, Message: err.Error()}, err
	}

	wsse, err := buildHuaweiWSSE(s.appKey, s.appSecret)
	if err != nil {
		return SendResult{Success: false, Message: err.Error()}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiURL, bytes.NewReader(payload))
	if err != nil {
		return SendResult{Success: false, Message: err.Error()}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", `WSSE realm="SDP", profile="UsernameToken", type="Appkey"`)
	httpReq.Header.Set("X-WSSE", wsse)

	resp, err := s.http.Do(httpReq)
	if err != nil {
		return SendResult{Success: false, Message: err.Error()}, fmt.Errorf("请求短信网关失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)

	var parsed struct {
		Code        string `json:"code"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(raw, &parsed)
	if parsed.Code != "" && parsed.Code != "000000" {
		hint := parsed.Description
		if hint == "" {
			hint = parsed.Code
		}
		return SendResult{Success: false, Message: hint, Response: json.RawMessage(raw)}, fmt.Errorf("%s", hint)
	}
	if resp.StatusCode >= 300 {
		return SendResult{Success: false, Message: string(raw), Response: json.RawMessage(raw)},
			fmt.Errorf("短信网关 HTTP %d", resp.StatusCode)
	}
	return SendResult{Success: true, Response: json.RawMessage(raw)}, nil
}

// resolveHuaweiAPIURL 对齐 sms4j：config.url + "/sms/batchSendSms/v1"。
// 若已带完整 path 则不再拼接，兼容库里直接存全路径的配置。
func resolveHuaweiAPIURL(raw string) string {
	base := strings.TrimSpace(raw)
	if base == "" {
		base = huaweiDefaultBase
	}
	base = strings.TrimRight(base, "/")
	if strings.HasSuffix(base, huaweiRequestPath) {
		return base
	}
	return base + huaweiRequestPath
}

func buildHuaweiWSSE(appKey, appSecret string) (string, error) {
	nonce := strings.ReplaceAll(uuid.NewString(), "-", "")
	created := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	sum := sha256.Sum256([]byte(nonce + created + appSecret))
	digest := base64.StdEncoding.EncodeToString(sum[:])
	return fmt.Sprintf(
		`UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"`,
		appKey, digest, nonce, created,
	), nil
}
