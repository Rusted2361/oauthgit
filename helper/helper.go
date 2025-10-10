package helper

import (
	"crypto/rand"
	"encoding/base64"

	"log"

	"os"
	
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	OauthConfig *oauth2.Config
)

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

func LoadEnv() (string, string, string, string) {
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

	if SessionKey == "" || GithubClientId == "" || GithubClientSecret == "" || BaseUrl == "" {
		log.Fatal("SESSION_KEY must be set")
	}
	//return session key
	return SessionKey, GithubClientId, GithubClientSecret, BaseUrl
}
