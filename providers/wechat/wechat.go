// Package wechat implements the OAuth2 protocol for authenticating users through WeChat.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package wechat

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"fmt"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL      string = "https://api.weixin.qq.com/sns/auth"
	tokenURL     string = "https://api.weixin.qq.com/sns/oauth2/access_token"
	endpointUser string = "https://api.weixin.qq.com/sns/userinfo"
)

// Provider is the implementation of `goth.Provider` for accessing WeChat.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// New creates a new WeChat provider and sets up important connection details.
// You should always call `wechat.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "wechat",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client returns a pointer to http.Client setting some client fallback.
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the wechat package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks WeChat for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to WeChat and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", endpointUser, nil)
	if err != nil {
		return user, err
	}
	req.Header.Add("Authorization", "Bearer "+sess.AccessToken)
	resp, err := p.Client().Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return user, err
	}

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	err = userFromReader(resp.Body, &user)
	return user, err
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		// The ID of an ordinary user, which is unique for the developer
		// account.
		OpenID   string `json:"openid"`
		NickName string `json:"nickname"`
		// The gender of an ordinary user. 1: male; 2: female.
		Sex int64 `json:"sex"`
		// The province entered in the ordinary user's personal information.
		Province string `json:"province"`
		// The city entered in the ordinary user's personal information.
		City string `json:"city"`
		// The country, e.g. CN for China.
		Country string `json:"country"`
		// Profile photo of a user. The last numeric value represents the
		// size of a square profile photo (The value can be 0, 46, 64, 96,
		// or 132. The value 0 represents a 640*640 square profile photo).
		// This parameter is left blank if a user has no profile photo.
		HeadImgURL string `json:"headimgurl"`
		// User privilege information, in the form of a JSON array. For example,
		// WeChat Woka users have the value "chinaunicom".
		Privileges []string `json:"privilege"`
		// The user's unified ID. A user's apps under the same WeChat Open
		// Platform account share the same UnionID.
		UnionID string `json:"unionid"`
	}{}

	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.NickName
	user.NickName = u.NickName
	user.AvatarURL = u.HeadImgURL
	user.Location = strings.Join([]string{u.City, u.Province, u.Country}, ", ")
	user.UserID = u.UnionID

	return nil
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	return c
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
