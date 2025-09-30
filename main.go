package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"oauthgit/handler"
	"oauthgit/models"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func main() {

	//use slogger as a logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Load env vars
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	fmt.Println(clientID)
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
	sessionKey := os.Getenv("SESSION_KEY")
	baseURL := os.Getenv("BASE_URL")

	if clientID == "" || clientSecret == "" || sessionKey == "" || baseURL == "" {
		log.Fatal("GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, SESSION_KEY and BASE_URL must be set")
	}

	models.OauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     github.Endpoint,
		Scopes:       []string{"user:email"},
		RedirectURL:  baseURL + "/callback",
	}

	models.Store = sessions.NewCookieStore([]byte(sessionKey))
	models.Store.Options = &sessions.Options{
		HttpOnly: true,
		Secure:   false, // set true in prod (requires HTTPS)
		Path:     "/",
		MaxAge:   86400 * 7,
	}

	r := mux.NewRouter()
	r.HandleFunc("/", handler.HandleHome).Methods("GET")
	r.HandleFunc("/login", handler.HandleLogin).Methods("GET")
	r.HandleFunc("/callback", handler.HandleCallback).Methods("GET")
	r.HandleFunc("/welcome", handler.HandleWelcome).Methods("GET")
	r.HandleFunc("/logout", handler.HandleLogout).Methods("POST")

	// Static or templates can be added here

	srv := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		log.Printf("Server starting on %s\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// Wait for interrupt
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}
	log.Println("Server exited gracefully")
}
