package main

import (
	"context"
	"log"
	"log/slog"
	"oauthgit/db/sqlc"
	"oauthgit/handler"

	"oauthgit/helper"
	"oauthgit/middlewares"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
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

	protected := router.Group("/")
	protected.Use(middlewares.JWTAuthMiddleware())
	{
		protected.GET("/welcome", handler.HandleWelcome)
		protected.GET("/user", handler.UserData)
		protected.POST("/static-analysis", handler.HandleStaticAnalysis)
		protected.GET("/user/followers", handler.UserFollowers)
		protected.GET("/analysis", handler.HandleAnalysisPage)
		protected.POST("/logout", handler.HandleLogout)

	}

	// http.Handle("/", router)
}

func main() {

	// Logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Env
	sessionKey, githubclient, githubsecret, BaseUrl, databaseURL := helper.LoadEnv()

	conn, err := pgx.Connect(context.Background(), databaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer conn.Close(context.Background())

	log.Println("✅ Successfully connected to database")

	// Create SQLC queries instance
	queries := sqlc.New(conn)

	// Set queries in helper package BEFORE setting up routes
	helper.SetQueries(queries)
	log.Println("✅ Database queries initialized")

	// OAuth
	helper.InitOauth(githubclient, githubsecret, BaseUrl)

	//create Routers
	router := gin.Default()

	// Sessions
	middlewares.InitSession(router, sessionKey)

	//register routes
	RegisterRoutes(router)

	//todo start server
	//run server
	// TODO: Step 3.5 - Use configurable port from config
	// Change to: err := router.Run(":" + cfg.ServerPort)
	err = router.Run()
	if err != nil {
		slog.Error("Failed to start server", "error", err)
		return
	}

	//todo stop server with graceful shutdown
}
