package sms

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const yunpianDefaultURL = "https://sms.yunpian.com/v2/sms/tpl_single_send.json"

type yunpianSender struct {
	apiKey string
	apiURL string
	http   *http.Client
}

func newYunpianSender(cred Credentials) (Sender, error) {
	if cred.AccessKeyID == "" {
		return nil, fmt.Errorf("sms: 云片 apikey 未配置（填入 accessKeyId）")
	}
	apiURL := strings.TrimSpace(cred.URL)
	if apiURL == "" {
		apiURL = yunpianDefaultURL
	}
	return &yunpianSender{
		apiKey: cred.AccessKeyID,
		apiURL: apiURL,
		http:   &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (s *yunpianSender) Send(ctx context.Context, req SendRequest) (SendResult, error) {
	if req.Phone == "" || req.TemplateCode == "" {
		return SendResult{Success: false, Message: "手机号或模板码为空"}, fmt.Errorf("sms: 手机号或模板码为空")
	}
	form := url.Values{}
	form.Set("apikey", s.apiKey)
	form.Set("mobile", req.Phone)
	form.Set("tpl_id", req.TemplateCode)
	form.Set("tpl_value", yunpianTplValue(req.Params))

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return SendResult{Success: false, Message: err.Error()}, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(httpReq)
	if err != nil {
		return SendResult{Success: false, Message: err.Error()}, fmt.Errorf("请求短信网关失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)

	var parsed struct {
		Code   int    `json:"code"`
		Msg    string `json:"msg"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(raw, &parsed)
	if parsed.Code != 0 {
		hint := parsed.Detail
		if hint == "" {
			hint = parsed.Msg
		}
		if hint == "" {
			hint = fmt.Sprintf("云片错误码 %d", parsed.Code)
		}
		return SendResult{Success: false, Message: hint, Response: json.RawMessage(raw)}, fmt.Errorf("%s", hint)
	}
	return SendResult{Success: true, Response: json.RawMessage(raw)}, nil
}

// yunpianTplValue 形如 #code#=1234&#min#=5（URL 编码由 form 完成，此处只拼明文）。
func yunpianTplValue(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	parts := make([]string, 0, len(params))
	for k, v := range params {
		parts = append(parts, "#"+k+"#="+v)
	}
	// map 遍历顺序不定；云片按变量名匹配，顺序无关。
	return strings.Join(parts, "&")
}
