package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	xoauth2 "golang.org/x/oauth2"
)

// qqProvider QQ 互联登录，对齐 JustAuth AuthQqRequest。
type qqProvider struct{}

func (qqProvider) oauthConfig(cfg ProviderConfig) (*xoauth2.Config, error) {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"get_user_info"}
	}
	return stubOAuthConfig(cfg, scopes), nil
}

func (qqProvider) authorizeURL(cfg ProviderConfig, state string) (string, error) {
	scope := "get_user_info"
	if len(cfg.Scopes) > 0 {
		scope = joinScopes(cfg.Scopes, ",")
	}
	return "https://graph.qq.com/oauth2.0/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURI},
		"state":         {state},
		"scope":         {scope},
	}.Encode(), nil
}

func (qqProvider) exchange(ctx context.Context, cfg ProviderConfig,
	client *http.Client, code string) (*xoauth2.Token, error) {

	// JustAuth：默认返回 access_token=...&expires_in=... 表单串，再 parseStringToMap。
	q := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {cfg.RedirectURI},
	}
	raw, err := doGETRaw(ctx, client, "https://graph.qq.com/oauth2.0/token?"+q.Encode())
	if err != nil {
		return nil, err
	}
	m := parseQueryOrJSON(raw)
	if m["access_token"] == "" || m["code"] != "" {
		return nil, fmt.Errorf("qq: %s", firstNonEmpty(m["msg"], m["error_description"], "换票失败"))
	}
	expiresIn, _ := strconv.Atoi(m["expires_in"])
	return tokenWithExpiry(m["access_token"], m["refresh_token"], expiresIn, nil), nil
}

func qqOpenID(ctx context.Context, client *http.Client, accessToken string, wantUnion bool) (openid, unionid string, err error) {
	union := "0"
	if wantUnion {
		union = "1"
	}
	endpoint := "https://graph.qq.com/oauth2.0/me?" + url.Values{
		"access_token": {accessToken},
		"unionid":      {union},
	}.Encode()
	raw, err := doGETRaw(ctx, client, endpoint)
	if err != nil {
		return "", "", err
	}
	body := strings.TrimSpace(raw)
	// JustAuth：剥 callback( ... );
	body = strings.TrimPrefix(body, "callback(")
	body = strings.TrimSuffix(strings.TrimSpace(body), ");")
	body = strings.TrimSpace(body)
	if i := strings.Index(body, "{"); i >= 0 {
		if j := strings.LastIndex(body, "}"); j > i {
			body = body[i : j+1]
		}
	}
	var parsed struct {
		OpenID    string `json:"openid"`
		UnionID   string `json:"unionid"`
		Error     any    `json:"error"`
		ErrorDesc string `json:"error_description"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return "", "", fmt.Errorf("qq: 解析 openid 失败: %w", err)
	}
	if parsed.OpenID == "" {
		return "", "", fmt.Errorf("qq: %s", firstNonEmpty(parsed.ErrorDesc, "未返回 openid"))
	}
	return parsed.OpenID, parsed.UnionID, nil
}

func (qqProvider) fetchUser(ctx context.Context, cfg ProviderConfig,
	client *http.Client, tok *xoauth2.Token) (*AuthUser, error) {

	openid, unionid, err := qqOpenID(ctx, client, tok.AccessToken, false)
	if err != nil {
		return nil, err
	}
	var u struct {
		Ret       int    `json:"ret"`
		Msg       string `json:"msg"`
		Nickname  string `json:"nickname"`
		FigureURL string `json:"figureurl_qq_2"`
		Figure1   string `json:"figureurl_qq_1"`
	}
	q := url.Values{
		"access_token":       {tok.AccessToken},
		"oauth_consumer_key": {cfg.ClientID},
		"openid":             {openid},
	}
	if err := doFormGET(ctx, client, "https://graph.qq.com/user/get_user_info", q, &u); err != nil {
		return nil, err
	}
	if u.Ret != 0 {
		return nil, fmt.Errorf("qq: %s (%d)", u.Msg, u.Ret)
	}
	at := tokenFrom(tok)
	at.OpenID = openid
	at.UnionID = unionid
	// JustAuth：uuid 优先 unionId，否则 openId；username/nickname 均为 nickname。
	uid := firstNonEmpty(unionid, openid)
	return &AuthUser{
		UUID:     uid,
		Source:   SourceQQ,
		Username: u.Nickname,
		Nickname: u.Nickname,
		Avatar:   firstNonEmpty(u.FigureURL, u.Figure1),
		Token:    at,
	}, nil
}
