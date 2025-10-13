package helper

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"oauthgit/db/sqlc"
	"oauthgit/models"

	"log"

	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	OauthConfig *oauth2.Config
	Queries     *sqlc.Queries
)

// SetQueries sets the database queries instance
func SetQueries(q *sqlc.Queries) {
	Queries = q
}

//todo write any helper if needed

//generate state token

func GenerateToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}

	sEnc := base64.URLEncoding.EncodeToString(token)

	return sEnc, nil
}

func InitOauth(githubclient, githubsecret, BaseUrl string) {
	//initialize github OauthConfig
	OauthConfig = &oauth2.Config{
		ClientID:     githubclient,
		ClientSecret: githubsecret,
		RedirectURL:  BaseUrl + "/callback",
		Scopes:       []string{"repo", "user:email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}
}

//function to load environment variables

func LoadEnv() (string, string, string, string, string) {
	//load .env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	//fetch session key
	SessionKey := os.Getenv("SESSION_KEY")
	GithubClientId := os.Getenv("GITHUB_CLIENT_ID")
	GithubClientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
	BaseUrl := os.Getenv("BASE_URL")
	databaseURL := os.Getenv("DATABASE_URL")

	if SessionKey == "" || GithubClientId == "" || GithubClientSecret == "" || BaseUrl == "" || databaseURL == "" {
		log.Fatal("SESSION_KEY must be set")
	}
	//return session key
	return SessionKey, GithubClientId, GithubClientSecret, BaseUrl, databaseURL
}

func StoreUserInDatabase(c *gin.Context, githubUser *models.GitHubUser, accessToken string) (*sqlc.User, error) {
	// Check if user already exists by GitHub ID
	existingUser, err := Queries.GetUserByGithubID(c, githubUser.ID)

	if err == nil {
		// User exists, update their token and information
		fmt.Printf("User already exists with ID %d, updating...\n", existingUser.ID)

		updatedUser, err := Queries.UpdateUser(c, sqlc.UpdateUserParams{
			ID:          existingUser.ID,
			Username:    githubUser.Login,
			Email:       &githubUser.Email,
			AvatarUrl:   &githubUser.AvatarURL,
			AccessToken: &accessToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}

		return &updatedUser, nil
	}

	// User doesn't exist, create new user
	fmt.Printf("Creating new user: %s (GitHub ID: %d)\n", githubUser.Login, githubUser.ID)

	newUser, err := Queries.CreateUser(c, sqlc.CreateUserParams{
		GithubID:    githubUser.ID,
		Username:    githubUser.Login,
		Email:       &githubUser.Email,
		AvatarUrl:   &githubUser.AvatarURL,
		AccessToken: &accessToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	fmt.Printf("✅ Created new user with ID: %d\n", newUser.ID)
	return &newUser, nil
}
