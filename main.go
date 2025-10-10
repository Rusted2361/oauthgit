package main

import (
	"log/slog"
	"net/http"
	"oauthgit/handler"
	"oauthgit/helper"
	"oauthgit/session"
	"os"

	"github.com/gin-gonic/gin"

	// TODO: Uncomment these imports after creating the respective packages:
	// "oauthgit/auth"
	// "oauthgit/config"
	// "oauthgit/middleware"
)

//todo write all handles for server home, login, callback, welcome, logout

func RegisterRoutes(router *gin.Engine) {
	// Public routes (no authentication required)
	router.GET("/", handler.HandleHome)
	router.GET("/login", handler.HandleLogin)
	router.GET("/callback", handler.HandleCallback)
	router.POST("/logout", handler.HandleLogout)

	// TODO: Step 4.1 - Create protected route group with JWT middleware
	// Uncomment the code below after completing Phase 3:
	//
	// protected := router.Group("/")
	// protected.Use(middleware.JWTAuthMiddleware(helper.JWTService))
	// {
	//     protected.GET("/welcome", handler.HandleWelcome)
	//     // TODO: Add more protected routes here as needed
	// }

	// TODO: Remove this line after moving /welcome to protected group above
	router.GET("/welcome", handler.HandleWelcome)

	http.Handle("/", router)
}

func main() {
	//use slog : done
	// Initialize slog logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// TODO: Step 3.3 - Load JWT configuration from environment
	// Uncomment after creating config package:
	//
	// cfg, err := config.Load()
	// if err != nil {
	//     slog.Error("Failed to load configuration", "error", err)
	//     os.Exit(1)
	// }
	// slog.Info("Configuration loaded successfully",
	//     "jwt_expiry", cfg.JWTExpiry,
	//     "server_port", cfg.ServerPort)

	//load env to config : done
	sessionKey, githubclient, githubsecret, BaseUrl := helper.LoadEnv()

	//initialize OauthConfig
	helper.InitOauth(githubclient, githubsecret, BaseUrl)

	// TODO: Step 3.4 - Initialize JWT service
	// Uncomment after completing Step 3.3:
	//
	// helper.JWTService = auth.NewJWTService(cfg.JWTSecret, cfg.JWTExpiry)
	// slog.Info("JWT service initialized successfully")

	//create Routers
	router := gin.Default()

	//initialize sessions middleware
	session.InitSession(router, sessionKey)

	//register routes
	RegisterRoutes(router)

	//todo start server
	//run server
	// TODO: Step 3.5 - Use configurable port from config
	// Change to: err := router.Run(":" + cfg.ServerPort)
	err := router.Run()
	if err != nil {
		slog.Error("Failed to start server", "error", err)
		return
	}

	//todo stop server with graceful shutdown
}
