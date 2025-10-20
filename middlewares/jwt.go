package middlewares

import (
	"fmt"
	"net/http"
	"oauthgit/helper"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		// Prefer JWT from session first; fallback to Authorization header or cookie
		session := sessions.Default(c)
		var tokenString string
		source := "unknown"
		if token, ok := session.Get("accesstoken").(string); ok && token != "" {
			tokenString = token
		} else {
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				tokenString = strings.TrimSpace(authHeader[len("Bearer "):])
				source = "authorization_header"
			} else if cookie, err := c.Cookie("token"); err == nil && cookie != "" {
				// Secondary fallback to cookie named "token"
				tokenString = cookie
				source = "cookie"
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid token"})
				c.Abort()
				return
			}
		}

		fmt.Println("JWT middleware: token sourced and verifying")
		// Verify JWT and extract user_id
		userID, err := helper.VerifyJWT(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		fmt.Println("JWT middleware: verified")

		// Store user_id in context for use in handlers
		c.Set("user_id", userID)
		c.Set("auth_source", source)
		c.Next()
	}
}
