package sms

import (
	"context"
	"fmt"
	"strings"

	"github.com/NikoHXX/framework-common-go/jsonx"
	openapiutil "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	dysmsapi "github.com/alibabacloud-go/dysmsapi-20170525/v5/client"
)

const (
	aliyunSuccessCode   = "OK"
	alibabaDefaultEP    = "dysmsapi.aliyuncs.com"
	alibabaDefaultRegion = "cn-hangzhou"
)

type alibabaSender struct {
	client    *dysmsapi.Client
	signature string
}

func newAlibabaSender(cred Credentials) (Sender, error) {
	if cred.AccessKeyID == "" || cred.AccessKeySecret == "" {
		return nil, fmt.Errorf("sms: 阿里云 AccessKey 未配置")
	}
	endpoint := strings.TrimSpace(cred.URL)
	if endpoint == "" {
		endpoint = alibabaDefaultEP
	}
	endpoint = strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	region := cred.RegionID
	if region == "" {
		region = alibabaDefaultRegion
	}
	ak, sk := cred.AccessKeyID, cred.AccessKeySecret
	cl, err := dysmsapi.NewClient(&openapiutil.Config{
		AccessKeyId:     &ak,
		AccessKeySecret: &sk,
		Endpoint:        &endpoint,
		RegionId:        &region,
	})
	if err != nil {
		return nil, fmt.Errorf("sms: 构造阿里云客户端失败: %w", err)
	}
	return &alibabaSender{client: cl, signature: cred.Signature}, nil
}

func (s *alibabaSender) Send(ctx context.Context, req SendRequest) (SendResult, error) {
	_ = ctx
	if req.Phone == "" || req.TemplateCode == "" {
		return SendResult{Success: false, Message: "手机号或模板码为空"}, fmt.Errorf("sms: 手机号或模板码为空")
	}
	if s.signature == "" {
		return SendResult{Success: false, Message: "短信签名未配置"}, fmt.Errorf("sms: 短信签名未配置")
	}
	paramBytes, err := jsonx.Marshal(req.Params)
	if err != nil {
		return SendResult{Success: false, Message: err.Error()}, err
	}
	paramStr := string(paramBytes)
	sign := s.signature
	phone, tpl := req.Phone, req.TemplateCode
	resp, err := s.client.SendSms(&dysmsapi.SendSmsRequest{
		PhoneNumbers:  &phone,
		SignName:      &sign,
		TemplateCode:  &tpl,
		TemplateParam: &paramStr,
	})
	if err != nil {
		return SendResult{Success: false, Message: err.Error(), Response: nil}, fmt.Errorf("请求短信网关失败: %w", err)
	}
	if resp == nil || resp.Body == nil || resp.Body.Code == nil {
		return SendResult{Success: false, Message: "短信网关返回空响应", Response: resp},
			fmt.Errorf("短信网关返回空响应")
	}
	if *resp.Body.Code != aliyunSuccessCode {
		hint := *resp.Body.Code
		if resp.Body.Message != nil && *resp.Body.Message != "" {
			hint = *resp.Body.Message
		}
		return SendResult{Success: false, Message: hint, Response: resp}, fmt.Errorf("%s", hint)
	}
	return SendResult{Success: true, Response: resp}, nil
}
