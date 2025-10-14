package helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"oauthgit/db/sqlc"
	"oauthgit/models"
	"strings"

	"log"

	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	OauthConfig *oauth2.Config
	Queries     *sqlc.Queries
	// EncryptionKey holds the symmetric key for encrypting tokens (32 bytes).
	EncryptionKey []byte
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
	tokenEncKeyB64 := os.Getenv("TOKEN_ENC_KEY")

	if SessionKey == "" || GithubClientId == "" || GithubClientSecret == "" || BaseUrl == "" || databaseURL == "" || tokenEncKeyB64 == "" {
		log.Fatal("SESSION_KEY must be set")
	}
	// Decode TOKEN_ENC_KEY (base64) to 32-byte key
	key, err := base64.StdEncoding.DecodeString(tokenEncKeyB64)
	if err != nil {
		log.Fatal("failed to decode TOKEN_ENC_KEY (base64)")
	}
	if len(key) != 32 {
		log.Fatal("TOKEN_ENC_KEY must be 32 bytes when base64-decoded")
	}
	EncryptionKey = key
	//return session key
	return SessionKey, GithubClientId, GithubClientSecret, BaseUrl, databaseURL
}

func StoreUserInDatabase(c *gin.Context, githubUser *models.GitHubUser, accessToken string) (*sqlc.User, error) {
	// Encrypt access token before storing
	encryptedToken, err := EncryptToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt access token: %w", err)
	}
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
			AccessToken: &encryptedToken,
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
		AccessToken: &encryptedToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	fmt.Printf("✅ Created new user with ID: %d\n", newUser.ID)
	return &newUser, nil
}

// EncryptToken encrypts a plaintext token using AES-GCM and returns base64(nonce|ciphertext).
func EncryptToken(plaintext string) (string, error) {
	if len(EncryptionKey) == 0 {
		return "", fmt.Errorf("encryption key is not initialized")
	}
	block, err := aes.NewCipher(EncryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	out := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// DecryptToken reverses EncryptToken and returns the plaintext token.
func DecryptToken(ciphertextB64 string) (string, error) {
	if len(EncryptionKey) == 0 {
		return "", fmt.Errorf("encryption key is not initialized")
	}
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(EncryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func CloneRepo(repoURL string, destinationPath, accessToken string) error {
	// Validate the repo URL
	if repoURL == "" {
		return fmt.Errorf("repository URL cannot be empty")
	}

	if accessToken == "" {
		return fmt.Errorf("access token cannot be empty")
	}

	// Convert SSH URL to HTTPS if needed
	authenticatedURL := buildAuthenticatedURL(repoURL, accessToken)

	// Clone the repository using go-git
	_, err := git.PlainClone(destinationPath, false, &git.CloneOptions{
		URL: authenticatedURL,
		Auth: &http.BasicAuth{
			Username: "oauth2", // Can be anything for token auth
			Password: accessToken,
		},
		Progress: os.Stdout, // Show clone progress
	})

	if err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	fmt.Printf("Successfully cloned repository to: %s\n", destinationPath)
	return nil
}

// buildAuthenticatedURL converts repo URL and injects the access token
func buildAuthenticatedURL(repoURL, accessToken string) string {
	// If it's an SSH URL (git@github.com:user/repo.git), convert to HTTPS
	if strings.HasPrefix(repoURL, "git@github.com:") {
		// Convert git@github.com:user/repo.git to https://token@github.com/user/repo.git
		repoURL = strings.Replace(repoURL, "git@github.com:", "github.com/", 1)
		return fmt.Sprintf("https://%s@%s", accessToken, repoURL)
	}

	// If it's already HTTPS (https://github.com/user/repo.git)
	if strings.HasPrefix(repoURL, "https://github.com/") {
		// Inject token: https://token@github.com/user/repo.git
		return strings.Replace(repoURL, "https://", fmt.Sprintf("https://%s@", accessToken), 1)
	}

	// If it's a simple github.com/user/repo format
	if strings.HasPrefix(repoURL, "github.com/") {
		return fmt.Sprintf("https://%s@%s", accessToken, repoURL)
	}

	// Return as-is if format is unknown
	return repoURL
}
