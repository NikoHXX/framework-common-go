// Package smshelper 保留 YAML 启动期 Init 的薄封装。
//
// 新代码请直接使用 github.com/NikoHXX/framework-common-go/sms。
// 本包仅服务仍走 yaml 配置的旧调用方；ahxlo 主路径已改 DB + sms.NewSender。
package smshelper

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/NikoHXX/framework-common-go/sms"
)

// ErrDisabled 短信功能未开启。
var ErrDisabled = errors.New("smshelper: 短信功能未开启")

var (
	enabled bool
	aliCred sms.Credentials
)

// Init 按 YAML SMSConfig 初始化（仅阿里云）。
func Init(c SMSConfig) {
	if !c.Enabled {
		log.Printf("[smshelper] 未开启")
		return
	}
	cred := sms.Credentials{
		AccessKeyID:     c.Aliyun.AccessKeyID,
		AccessKeySecret: c.Aliyun.AccessKeySecret,
		Signature:       c.Captcha.SignName, // 校验用；实际发信仍以 SendByAli 入参为准
		URL:             c.Aliyun.Endpoint,
		RegionID:        c.Aliyun.RegionID,
	}
	if _, err := sms.NewSender(sms.SupplierAlibaba, cred); err != nil {
		log.Printf("[smshelper] 阿里云渠道未就绪: %v", err)
		return
	}
	aliCred = cred
	enabled = true
	log.Printf("[smshelper] 已就绪")
}

// Enabled 是否可用。
func Enabled() bool { return enabled }

// SendByAli 用阿里云渠道发一条短信，未就绪时返回 ErrDisabled。
// templateParam 接受 map[string]string 或可忽略的其它类型（非 map 则空参数）。
func SendByAli(phone, signName, templateCode string, templateParam any) error {
	if !enabled {
		return ErrDisabled
	}
	if signName == "" || templateCode == "" {
		return fmt.Errorf("smshelper: signName / templateCode 未传入")
	}
	cred := aliCred
	cred.Signature = signName
	sender, err := sms.NewSender(sms.SupplierAlibaba, cred)
	if err != nil {
		return err
	}
	params := asStringMap(templateParam)
	res, err := sender.Send(context.Background(), sms.SendRequest{
		Phone:        phone,
		TemplateCode: templateCode,
		Params:       params,
	})
	if err != nil {
		if res.Message != "" {
			return fmt.Errorf("smshelper: 短信发送失败: %s", res.Message)
		}
		return fmt.Errorf("smshelper: %w", err)
	}
	return nil
}

func asStringMap(v any) map[string]string {
	switch m := v.(type) {
	case map[string]string:
		return m
	case map[string]any:
		out := make(map[string]string, len(m))
		for k, val := range m {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
		return out
	default:
		return nil
	}
}
