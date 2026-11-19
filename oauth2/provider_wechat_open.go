package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	xoauth2 "golang.org/x/oauth2"
)

// wechatOpenProvider 微信开放平台扫码登录，对齐 JustAuth AuthWeChatOpenRequest。
type wechatOpenProvider struct{}

func (wechatOpenProvider) oauthConfig(cfg ProviderConfig) (*xoauth2.Config, error) {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"snsapi_login"}
	}
	return stubOAuthConfig(cfg, scopes), nil
}

func (wechatOpenProvider) authorizeURL(cfg ProviderConfig, state string) (string, error) {
	// JustAuth AuthWeChatOpenRequest#authorize：无 #wechat_redirect 片段。
	return "https://open.weixin.qq.com/connect/qrconnect?" + url.Values{
		"response_type": {"code"},
		"appid":         {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURI},
		"scope":         {"snsapi_login"},
		"state":         {state},
	}.Encode(), nil
}

func (wechatOpenProvider) exchange(ctx context.Context, cfg ProviderConfig,
	client *http.Client, code string) (*xoauth2.Token, error) {

	var resp struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		OpenID       string `json:"openid"`
		UnionID      string `json:"unionid"`
		ErrCode      int    `json:"errcode"`
		ErrMsg       string `json:"errmsg"`
	}
	q := url.Values{
		"code":       {code},
		"appid":      {cfg.ClientID},
		"secret":     {cfg.ClientSecret},
		"grant_type": {"authorization_code"},
	}
	if err := doFormGET(ctx, client, "https://api.weixin.qq.com/sns/oauth2/access_token", q, &resp); err != nil {
		return nil, err
	}
	if resp.ErrCode != 0 || resp.AccessToken == "" {
		return nil, fmt.Errorf("wechat_open: %s (%d)", firstNonEmpty(resp.ErrMsg, "换票失败"), resp.ErrCode)
	}
	return tokenWithExpiry(resp.AccessToken, resp.RefreshToken, resp.ExpiresIn, map[string]any{
		"openid":  resp.OpenID,
		"unionid": resp.UnionID,
	}), nil
}

func (wechatOpenProvider) fetchUser(ctx context.Context, _ ProviderConfig,
	client *http.Client, tok *xoauth2.Token) (*AuthUser, error) {

	openid, _ := tok.Extra("openid").(string)
	if openid == "" {
		return nil, fmt.Errorf("oauth2: wechat_open 未返回 openid")
	}
	var u struct {
		OpenID     string `json:"openid"`
		Nickname   string `json:"nickname"`
		HeadImgURL string `json:"headimgurl"`
		UnionID    string `json:"unionid"`
		ErrCode    int    `json:"errcode"`
		ErrMsg     string `json:"errmsg"`
	}
	q := url.Values{
		"access_token": {tok.AccessToken},
		"openid":       {openid},
		"lang":         {"zh_CN"},
	}
	if err := doFormGET(ctx, client, "https://api.weixin.qq.com/sns/userinfo", q, &u); err != nil {
		return nil, err
	}
	if u.ErrCode != 0 {
		return nil, fmt.Errorf("wechat_open: %s (%d)", u.ErrMsg, u.ErrCode)
	}
	at := tokenFrom(tok)
	at.OpenID = firstNonEmpty(u.OpenID, openid)
	if u.UnionID != "" {
		at.UnionID = u.UnionID
	}
	return &AuthUser{
		UUID:     at.OpenID,
		Source:   SourceWechatOpen,
		Username: u.Nickname,
		Nickname: u.Nickname,
		Avatar:   u.HeadImgURL,
		Token:    at,
	}, nil
}
