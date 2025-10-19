package helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"oauthgit/db/sqlc"
	"oauthgit/models"
	"os/exec"
	"strings"
	"time"

	"log"

	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	OauthConfig *oauth2.Config
	Queries     *sqlc.Queries
	// EncryptionKey holds the symmetric key for encrypting tokens (32 bytes).
	EncryptionKey []byte
	// BaseURL is the externally reachable base URL of this service.
	BaseURL string
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
	BaseURL = BaseUrl
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

// CreateRepoWebhook registers a webhook on the provided repository using the caller's token.
// It subscribes to PR-related events and points to BaseURL + "/webhook/github".
func CreateRepoWebhook(owner, repo, accessToken, webhookSecret string) error {
	if owner == "" || repo == "" {
		return fmt.Errorf("owner and repo are required")
	}
	if accessToken == "" {
		return fmt.Errorf("access token is required")
	}
	if BaseURL == "" {
		return fmt.Errorf("base URL is not configured")
	}

	hookURL := BaseURL + "/webhook/github"
	payload := map[string]any{
		"name":   "web",
		"active": true,
		"events": []string{"pull_request", "pull_request_review_comment", "check_suite", "check_run"},
		"config": map[string]any{
			"url":          hookURL,
			"content_type": "json",
			"secret":       webhookSecret,
			"insecure_ssl": "0",
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://api.github.com/repos/%s/%s/hooks", owner, repo), strings.NewReader(string(bodyBytes)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create webhook: %s - %s", resp.Status, string(respBody))
	}
	return nil
}

// GetRepoMetadata fetches repository metadata from GitHub and returns github_id, full name, owner, and name.
func GetRepoMetadata(owner, repo, accessToken string) (githubID int64, fullName, ownerOut, nameOut string, err error) {
	if owner == "" || repo == "" {
		return 0, "", "", "", fmt.Errorf("owner and repo are required")
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo), nil)
	if err != nil {
		return 0, "", "", "", err
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "token "+accessToken)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return 0, "", "", "", fmt.Errorf("failed to fetch repo: %s - %s", resp.Status, string(b))
	}
	var data struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
		Name     string `json:"name"`
		Owner    struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&data); err != nil {
		return 0, "", "", "", err
	}
	return data.ID, data.FullName, data.Owner.Login, data.Name, nil
}

// ParseRepoInput accepts inputs like "owner/repo" or an HTTPS/SSH URL and returns owner, repo.
func ParseRepoInput(input string) (string, string) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", ""
	}
	if strings.Contains(s, "github.com") {
		s = strings.TrimSuffix(s, ".git")
		s = strings.TrimPrefix(s, "https://")
		s = strings.TrimPrefix(s, "http://")
		s = strings.TrimPrefix(s, "git@")
		s = strings.TrimPrefix(s, "github.com:")
		s = strings.TrimPrefix(s, "github.com/")
		parts := strings.Split(s, "/")
		if len(parts) >= 2 {
			return parts[0], parts[1]
		}
		return "", ""
	}
	if strings.Count(s, "/") == 1 {
		parts := strings.SplitN(s, "/", 2)
		return parts[0], parts[1]
	}
	return "", ""
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

// CloneRepo clones a Git repository using the system's git command.
func CloneRepo(repoURL, destinationPath, accessToken string) error {
	// Validate inputs
	if repoURL == "" {
		return fmt.Errorf("repository URL cannot be empty")
	}
	if accessToken == "" {
		return fmt.Errorf("access token cannot be empty")
	}

	if destinationPath == "" {
		return fmt.Errorf("destination path cannot be empty")
	}

	// Convert SSH to HTTPS if needed
	authenticatedURL := buildAuthenticatedURL(repoURL, accessToken)

	// Prepare git clone command
	cmd := exec.Command("git", "clone", authenticatedURL, destinationPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("Cloning repository from %s...\n", repoURL)

	//todo check if repository is already cloned remove it
	os.RemoveAll(destinationPath)

	// Run the command
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	fmt.Printf("Successfully cloned repository to: %s\n", destinationPath)
	return nil
}

// buildAuthenticatedURL converts a repo URL into an HTTPS URL with the token.
func buildAuthenticatedURL(repoURL, accessToken string) string {
	// Example:
	// Input:  https://github.com/user/repo.git
	// Output: https://<token>@github.com/user/repo.git
	if strings.HasPrefix(repoURL, "https://") {
		return strings.Replace(repoURL, "https://", fmt.Sprintf("https://%s@", accessToken), 1)
	}

	// Handle SSH-style URLs (git@github.com:user/repo.git)
	if strings.HasPrefix(repoURL, "git@") {
		repoURL = strings.TrimPrefix(repoURL, "git@")
		repoURL = strings.Replace(repoURL, ":", "/", 1)
		return fmt.Sprintf("https://%s@%s", accessToken, repoURL)
	}

	return repoURL
}

// In helper/helper.go
func GenerateJWT(userID int64, username string) (string, error) {
	claims := &models.Claims{
		UserID:   userID,
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	sec := os.Getenv("JWT_SECRET")
	fmt.Println("sec", sec)
	return token.SignedString([]byte(sec))
}

func VerifyJWT(tokenString string) (int64, error) {
	claims := &models.Claims{}
	sec := os.Getenv("JWT_SECRET")
	fmt.Println("sec", sec)
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(sec), nil
	})
	fmt.Println("tpken", token)
	fmt.Println("claims", claims.UserID)

	if err != nil || !token.Valid {
		return 0, err
	}

	return claims.UserID, nil
}
