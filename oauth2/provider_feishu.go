package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	xoauth2 "golang.org/x/oauth2"
)

// feishuProvider 飞书企业自建应用登录，对齐 JustAuth AuthFeishuRequest。
type feishuProvider struct{}

func (feishuProvider) oauthConfig(cfg ProviderConfig) (*xoauth2.Config, error) {
	return stubOAuthConfig(cfg, cfg.Scopes), nil
}

func (feishuProvider) authorizeURL(cfg ProviderConfig, state string) (string, error) {
	// JustAuth 会对 redirect_uri 做 URL Encode；url.Values.Encode 同样会编码。
	return "https://open.feishu.cn/open-apis/authen/v1/index?" + url.Values{
		"app_id":       {cfg.ClientID},
		"redirect_uri": {cfg.RedirectURI},
		"state":        {state},
	}.Encode(), nil
}

func (feishuProvider) exchange(ctx context.Context, cfg ProviderConfig,
	client *http.Client, code string) (*xoauth2.Token, error) {

	appToken, err := feishuAppAccessToken(ctx, client, cfg.ClientID, cfg.ClientSecret)
	if err != nil {
		return nil, err
	}
	// JustAuth：app_access_token 放 JSON body，不走 Authorization 头。
	var resp struct {
		Code    int    `json:"code"`
		Msg     string `json:"msg"`
		Message string `json:"message"`
		Data    struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
			TokenType    string `json:"token_type"`
			OpenID       string `json:"open_id"`
			UnionID      string `json:"union_id"`
		} `json:"data"`
	}
	err = doJSON(ctx, client, http.MethodPost, "https://open.feishu.cn/open-apis/authen/v1/access_token",
		nil, map[string]string{
			"app_access_token": appToken,
			"grant_type":       "authorization_code",
			"code":             code,
		}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 || resp.Data.AccessToken == "" {
		return nil, fmt.Errorf("feishu: %s (%d)",
			firstNonEmpty(resp.Message, resp.Msg, "换票失败"), resp.Code)
	}
	return tokenWithExpiry(resp.Data.AccessToken, resp.Data.RefreshToken, resp.Data.ExpiresIn, map[string]any{
		"openid":     resp.Data.OpenID,
		"unionid":    resp.Data.UnionID,
		"token_type": resp.Data.TokenType,
	}), nil
}

func feishuAppAccessToken(ctx context.Context, client *http.Client, appID, appSecret string) (string, error) {
	var resp struct {
		Code           int    `json:"code"`
		Msg            string `json:"msg"`
		Message        string `json:"message"`
		AppAccessToken string `json:"app_access_token"`
		Expire         int    `json:"expire"`
	}
	// JustAuth 使用带尾斜杠的 internal/ 地址。
	err := doJSON(ctx, client, http.MethodPost,
		"https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/",
		nil, map[string]string{"app_id": appID, "app_secret": appSecret}, &resp)
	if err != nil {
		return "", err
	}
	if resp.Code != 0 || resp.AppAccessToken == "" {
		return "", fmt.Errorf("feishu: 获取 app_access_token 失败: %s (%d)",
			firstNonEmpty(resp.Message, resp.Msg), resp.Code)
	}
	return resp.AppAccessToken, nil
}

func (feishuProvider) fetchUser(ctx context.Context, _ ProviderConfig,
	client *http.Client, tok *xoauth2.Token) (*AuthUser, error) {

	var resp struct {
		Code    int    `json:"code"`
		Msg     string `json:"msg"`
		Message string `json:"message"`
		Data    struct {
			Name      string `json:"name"`
			AvatarURL string `json:"avatar_url"`
			OpenID    string `json:"open_id"`
			UnionID   string `json:"union_id"`
			Email     string `json:"email"`
		} `json:"data"`
	}
	if err := doJSON(ctx, client, http.MethodGet, "https://open.feishu.cn/open-apis/authen/v1/user_info",
		bearerHeader(tok.AccessToken), nil, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("feishu: %s (%d)", firstNonEmpty(resp.Message, resp.Msg), resp.Code)
	}
	// JustAuth：uuid = union_id。
	if resp.Data.UnionID == "" {
		return nil, fmt.Errorf("oauth2: feishu 未返回 union_id")
	}
	at := tokenFrom(tok)
	at.OpenID = firstNonEmpty(resp.Data.OpenID, at.OpenID)
	at.UnionID = resp.Data.UnionID
	return &AuthUser{
		UUID:     resp.Data.UnionID,
		Source:   SourceFeishu,
		Username: resp.Data.Name,
		Nickname: resp.Data.Name,
		Avatar:   resp.Data.AvatarURL,
		Email:    resp.Data.Email,
		Token:    at,
	}, nil
}
