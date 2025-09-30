package models

import (
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

const (
	SessionName     = "oauth-session"
	SessionStateKey = "oauth_state"
	SessionUserKey  = "user"
)

var (
	OauthConfig *oauth2.Config
	Store       *sessions.CookieStore
	BaseURL     string // e.g. http://localhost:8080
)

type GitHubUser struct {
	Login     string `json:"login"`
	ID        int64  `json:"id"`
	AvatarURL string `json:"avatar_url"`
	Name      string `json:"name"`
	Email     string `json:"email"`
}
