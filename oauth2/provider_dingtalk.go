package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	xoauth2 "golang.org/x/oauth2"
)

// dingtalkProvider 钉钉扫码登录 V2，对齐 JustAuth AuthDingTalkV2Request / AuthDefaultSource.DINGTALK_V2。
type dingtalkProvider struct{}

func (dingtalkProvider) oauthConfig(cfg ProviderConfig) (*xoauth2.Config, error) {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	return stubOAuthConfig(cfg, scopes), nil
}

func (dingtalkProvider) authorizeURL(cfg ProviderConfig, state string) (string, error) {
	scope := "openid"
	if len(cfg.Scopes) > 0 {
		scope = joinScopes(cfg.Scopes, ",")
	}
	// JustAuth：https://login.dingtalk.com/oauth2/challenge.htm
	return "https://login.dingtalk.com/oauth2/challenge.htm?" + url.Values{
		"response_type": {"code"},
		"client_id":     {cfg.ClientID},
		"scope":         {scope},
		"redirect_uri":  {cfg.RedirectURI},
		"prompt":        {"consent"},
		"state":         {state},
	}.Encode(), nil
}

func (dingtalkProvider) exchange(ctx context.Context, cfg ProviderConfig,
	client *http.Client, code string) (*xoauth2.Token, error) {

	var resp struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpireIn     int    `json:"expireIn"`
		CorpID       string `json:"corpId"`
	}
	err := doJSON(ctx, client, http.MethodPost, "https://api.dingtalk.com/v1.0/oauth2/userAccessToken",
		nil, map[string]string{
			"grantType":    "authorization_code",
			"clientId":     cfg.ClientID,
			"clientSecret": cfg.ClientSecret,
			"code":         code,
		}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.AccessToken == "" {
		return nil, fmt.Errorf("dingtalk: 换票未返回 accessToken")
	}
	return tokenWithExpiry(resp.AccessToken, resp.RefreshToken, resp.ExpireIn, map[string]any{
		"corpId": resp.CorpID,
	}), nil
}

func (dingtalkProvider) fetchUser(ctx context.Context, _ ProviderConfig,
	client *http.Client, tok *xoauth2.Token) (*AuthUser, error) {

	var u struct {
		Nick      string `json:"nick"`
		AvatarURL string `json:"avatarUrl"`
		OpenID    string `json:"openId"`
		UnionID   string `json:"unionId"`
		Email     string `json:"email"`
	}
	header := http.Header{"x-acs-dingtalk-access-token": []string{tok.AccessToken}}
	if err := doJSON(ctx, client, http.MethodGet, "https://api.dingtalk.com/v1.0/contact/users/me",
		header, nil, &u); err != nil {
		return nil, err
	}
	// JustAuth：uuid = unionId。
	if u.UnionID == "" {
		return nil, fmt.Errorf("oauth2: dingtalk 未返回 unionId")
	}
	at := tokenFrom(tok)
	at.OpenID = u.OpenID
	at.UnionID = u.UnionID
	return &AuthUser{
		UUID:     u.UnionID,
		Source:   SourceDingtalk,
		Username: u.Nick,
		Nickname: u.Nick,
		Avatar:   u.AvatarURL,
		Email:    u.Email,
		Token:    at,
	}, nil
}
