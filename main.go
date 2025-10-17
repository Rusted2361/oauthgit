package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"oauthgit/db/sqlc"
	"oauthgit/handler"

	"oauthgit/helper"
	"oauthgit/session"
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
	router.POST("/logout", handler.HandleLogout)
	router.POST("/CloneRepo", handler.HandleCloneRepo)
	router.POST("/repos/register", handler.HandleRegisterRepo)
	router.POST("/webhook/github", handler.HandleGithubWebhook)
	router.GET("/analysis", handler.HandleAnalysisPage)
	router.GET("/user", handler.UserData)
	// router.POST("/staticAnalysis", handler.HandleStaticAnalysis)
	router.POST("/staticAnalysis", handler.HandleStaticAnalysis)
	router.POST("/prreview", handler.HandlePRReview)

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

	//load env to config : done
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

	//initialize OauthConfig
	helper.InitOauth(githubclient, githubsecret, BaseUrl)

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
	err = router.Run()
	if err != nil {
		slog.Error("Failed to start server", "error", err)
		return
	}

	//todo stop server with graceful shutdown
}
