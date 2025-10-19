package middlewares

import (
	"fmt"
	"net/http"
	"oauthgit/helper"
	"strings"

	"github.com/gin-gonic/gin"
)

func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid token"})
			c.Abort()
			return
		}
		fmt.Println("i am in hwt middlewarte")

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		fmt.Println("24")
		// Verify JWT and extract user_id
		userID, err := helper.VerifyJWT(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		fmt.Println(32)

		// Store user_id in context for use in handlers
		c.Set("user_id", userID)
		c.Next()
	}
}
