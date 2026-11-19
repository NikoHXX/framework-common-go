package sms

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	tencentDefaultHost   = "sms.tencentcloudapi.com"
	tencentDefaultRegion = "ap-guangzhou"
	tencentService       = "sms"
	tencentAction        = "SendSms"
	tencentVersion       = "2021-01-11"
)

type tencentSender struct {
	secretID  string
	secretKey string
	sdkAppID  string
	signature string
	region    string
	host      string
	http      *http.Client
}

func newTencentSender(cred Credentials) (Sender, error) {
	if cred.AccessKeyID == "" || cred.AccessKeySecret == "" {
		return nil, fmt.Errorf("sms: 腾讯云 SecretId/SecretKey 未配置")
	}
	if cred.SdkAppID == "" {
		return nil, fmt.Errorf("sms: 腾讯云 SdkAppId 未配置")
	}
	region := cred.RegionID
	if region == "" {
		region = tencentDefaultRegion
	}
	// 腾讯自定义接入点可复用 URL 字段；空则官方默认。
	host := cred.URL
	if host == "" {
		host = tencentDefaultHost
	}
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	return &tencentSender{
		secretID:  cred.AccessKeyID,
		secretKey: cred.AccessKeySecret,
		sdkAppID:  cred.SdkAppID,
		signature: cred.Signature,
		region:    region,
		host:      host,
		http:      &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (s *tencentSender) Send(ctx context.Context, req SendRequest) (SendResult, error) {
	if req.Phone == "" || req.TemplateCode == "" {
		return SendResult{Success: false, Message: "手机号或模板码为空"}, fmt.Errorf("sms: 手机号或模板码为空")
	}
	phone := normalizeCNPhoneE164(req.Phone)
	payload := map[string]any{
		"PhoneNumberSet":   []string{phone},
		"SmsSdkAppId":      s.sdkAppID,
		"TemplateId":       req.TemplateCode,
		"TemplateParamSet": orderedParamValues(req),
	}
	if s.signature != "" {
		payload["SignName"] = s.signature
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return SendResult{Success: false, Message: err.Error()}, err
	}

	now := time.Now().UTC()
	headers, err := s.signTC3(now, body)
	if err != nil {
		return SendResult{Success: false, Message: err.Error()}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+s.host, bytes.NewReader(body))
	if err != nil {
		return SendResult{Success: false, Message: err.Error()}, err
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	httpReq.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := s.http.Do(httpReq)
	if err != nil {
		return SendResult{Success: false, Message: err.Error()}, fmt.Errorf("请求短信网关失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)

	var parsed struct {
		Response struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
			SendStatusSet []struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"SendStatusSet"`
		} `json:"Response"`
	}
	_ = json.Unmarshal(raw, &parsed)
	if parsed.Response.Error != nil {
		hint := parsed.Response.Error.Message
		if hint == "" {
			hint = parsed.Response.Error.Code
		}
		return SendResult{Success: false, Message: hint, Response: json.RawMessage(raw)}, fmt.Errorf("%s", hint)
	}
	if len(parsed.Response.SendStatusSet) > 0 {
		st := parsed.Response.SendStatusSet[0]
		if !strings.EqualFold(st.Code, "Ok") {
			hint := st.Message
			if hint == "" {
				hint = st.Code
			}
			return SendResult{Success: false, Message: hint, Response: json.RawMessage(raw)}, fmt.Errorf("%s", hint)
		}
	}
	if resp.StatusCode >= 300 {
		return SendResult{Success: false, Message: string(raw), Response: json.RawMessage(raw)},
			fmt.Errorf("短信网关 HTTP %d", resp.StatusCode)
	}
	return SendResult{Success: true, Response: json.RawMessage(raw)}, nil
}

func (s *tencentSender) signTC3(now time.Time, payload []byte) (map[string]string, error) {
	timestamp := fmt.Sprintf("%d", now.Unix())
	date := now.Format("2006-01-02")
	canonicalHeaders := "content-type:application/json; charset=utf-8\nhost:" + s.host + "\n"
	signedHeaders := "content-type;host"
	hashedPayload := sha256Hex(payload)
	canonicalRequest := strings.Join([]string{
		"POST", "/", "", canonicalHeaders, signedHeaders, hashedPayload,
	}, "\n")

	credentialScope := date + "/" + tencentService + "/tc3_request"
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256", timestamp, credentialScope, sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	secretDate := hmacSHA256([]byte("TC3"+s.secretKey), date)
	secretService := hmacSHA256(secretDate, tencentService)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	authorization := fmt.Sprintf(
		"TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.secretID, credentialScope, signedHeaders, signature,
	)
	return map[string]string{
		"Authorization":  authorization,
		"Host":           s.host,
		"X-TC-Action":    tencentAction,
		"X-TC-Timestamp": timestamp,
		"X-TC-Version":   tencentVersion,
		"X-TC-Region":    s.region,
	}, nil
}

func normalizeCNPhoneE164(phone string) string {
	phone = strings.TrimSpace(phone)
	if strings.HasPrefix(phone, "+") {
		return phone
	}
	if strings.HasPrefix(phone, "86") && len(phone) > 11 {
		return "+" + phone
	}
	return "+86" + phone
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(data))
	return m.Sum(nil)
}
