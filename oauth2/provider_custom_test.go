package oauth2

import (
	"strings"
	"testing"
)

func TestNormalizeSourceAliases(t *testing.T) {
	cases := map[string]string{
		"wechat":       SourceWechatOpen,
		"WEIXIN":       SourceWechatOpen,
		"lark":         SourceFeishu,
		"dingding":     SourceDingtalk,
		"dingtalk_v2":  SourceDingtalk,
		"wechat_open":  SourceWechatOpen,
		"qq":           SourceQQ,
		"dingtalk":     SourceDingtalk,
		"feishu":       SourceFeishu,
	}
	for in, want := range cases {
		if got := normalizeSource(in); got != want {
			t.Fatalf("normalizeSource(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCustomAuthorizeURLs(t *testing.T) {
	cfg := ProviderConfig{
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURI:  "https://app.example/cb",
	}
	state := "st-1"

	checks := []struct {
		name string
		p    authorizeBuilder
		want []string
	}{
		{"wechat", wechatOpenProvider{}, []string{
			"https://open.weixin.qq.com/connect/qrconnect?",
			"appid=cid",
			"response_type=code",
			"scope=snsapi_login",
			"state=st-1",
		}},
		{"dingtalk", dingtalkProvider{}, []string{
			"https://login.dingtalk.com/oauth2/challenge.htm?",
			"client_id=cid",
			"response_type=code",
			"scope=openid",
			"prompt=consent",
			"state=st-1",
		}},
		{"feishu", feishuProvider{}, []string{
			"https://open.feishu.cn/open-apis/authen/v1/index?",
			"app_id=cid",
			"state=st-1",
		}},
		{"qq", qqProvider{}, []string{
			"https://graph.qq.com/oauth2.0/authorize?",
			"client_id=cid",
			"response_type=code",
			"scope=get_user_info",
			"state=st-1",
		}},
	}
	for _, c := range checks {
		u, err := c.p.authorizeURL(cfg, state)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, w := range c.want {
			if !strings.Contains(u, w) {
				t.Fatalf("%s url missing %q\nurl=%s", c.name, w, u)
			}
		}
	}
}

func TestBuiltinProvidersCoverMajorSources(t *testing.T) {
	for _, s := range []string{
		SourceWechatOpen, SourceDingtalk, SourceFeishu, SourceQQ,
		SourceGitee, SourceGithub, SourceMaxkey, SourceTopiam,
	} {
		if _, ok := builtinProviders[s]; !ok {
			t.Fatalf("missing provider for %s", s)
		}
	}
	if _, ok := builtinProviders["microsoft"]; ok {
		t.Fatal("microsoft should not be registered")
	}
}
