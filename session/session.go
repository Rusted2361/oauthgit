package session

import (
	"encoding/gob"
	"oauthgit/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

const sessionName = "gitoauth-session"

func InitSession(router *gin.Engine, sessionKey string) {
	// Initialize session middleware
	// pass authKey[sessionkey to the Newstore]
	cookieStore := cookie.NewStore([]byte(sessionKey))
	//cookieStore.Options(
	//	sessions.Options{
	//		Path:     "/",
	//		MaxAge:   86400 * 30,
	//		HttpOnly: true,
	//	})
	router.Use(sessions.Sessions(sessionName, cookieStore))
	gob.Register(models.GitHubUser{})
}
