package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"oauthgit/helper"
	"oauthgit/models"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"golang.org/x/oauth2"
)

const (
	SessionStateKey = "oauth_state"
)

func HandleHome(c *gin.Context) {
	//todo
	html := `<!doctype html>
		<html>
		<head><title>Login</title></head>
		<body>
		  <h1>Login</h1>
		  <p>Welcome! Click the button to continue.</p>
		  <form method="get" action="/login">
			<button type="submit">Login</button>
		  </form>
		</body>
		</html>`

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// HandleLogin starts the OAuth flow:
// 1) Generate a CSRF-resistant state token
// 2) Store the state in the user's session cookie
// 3) Redirect the user to the provider's authorization URL
func HandleLogin(c *gin.Context) {
	//todo
	// Generate a random, CSRF-resistant state string (base64 encoded)
	state, err := helper.GenerateToken()
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to generate state")
		return
	}
	//fmt.Println(state)

	// Open or create a session for the user
	session := sessions.Default(c)

	// Store the generated state inside the session
	session.Set(SessionStateKey, state)

	// Save the session to persist the cookie
	err = session.Save()
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to save session")
		return
	}
	// Build the GitHub authorization URL using OAuth config and the state
	gitAuthURL := helper.OauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	fmt.Println("gitAuthURL", gitAuthURL)
	// Redirect the user to that GitHub authorization URL
	c.Redirect(http.StatusFound, gitAuthURL)

}

func HandleCallback(c *gin.Context) {
	source := c.GetString("auth_source")
	fmt.Println("auth source:", source)
	//todo
	// Retrieve the session for this request
	session := sessions.Default(c)

	// Read the stored state from the session
	state := session.Get(SessionStateKey)
	fmt.Println("state", state)

	// Compare stored state with 'state' query parameter to prevent CSRF
	queryState := c.Request.URL.Query().Get("state")
	fmt.Println(queryState)

	if queryState != state {
		c.String(http.StatusBadRequest, "Invalid state parameter using wrong CSRF token")
		return
	}

	// Get 'code' query parameter from URL
	queryCode := c.Request.URL.Query().Get("code")
	fmt.Println(queryCode)

	// Exchange the code for an access token using OAuth config
	token, err := helper.OauthConfig.Exchange(c, queryCode)
	if err != nil {
		http.Error(c.Writer, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	accessToken := token.AccessToken
	fmt.Println("accessToken", accessToken)

	// Create an OAuth client using the returned token
	client := helper.OauthConfig.Client(c, token)
	//fmt.Println("client", client)

	// Call GitHub API to fetch the authenticated user's info
	response, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(c.Writer, "Failed to fetch user data", http.StatusInternalServerError)
		return
	}
	//fmt.Println("response", response)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		http.Error(c.Writer, "Failed to read user data", http.StatusInternalServerError)
		return
	}

	fmt.Println("body", string(body))
	var user models.GitHubUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		http.Error(c.Writer, "Failed to parse user data", http.StatusInternalServerError)
		return
	}
	fmt.Println("user", user)
	// === NEW: Store user in database ===
	dbUser, err := helper.StoreUserInDatabase(c, &user, accessToken)
	if err != nil {
		fmt.Printf("❌ Failed to store user in database: %v\n", err)
		http.Error(c.Writer, "Failed to store user data", http.StatusInternalServerError)
		return
	}
	fmt.Printf("✅ User stored/updated in database: ID=%d, Username=%s\n", dbUser.ID, dbUser.Username)

	// Generate JWT with user info
	jwtToken, err := helper.GenerateJWT(dbUser.ID, user.Login)
	if err != nil {
		http.Error(c.Writer, "Failed to generate JWT", http.StatusInternalServerError)
		return
	}

	session.Set("accesstoken", jwtToken)

	// // Store the user info inside the session (now includes database ID)
	// //fmt.Println("=== SESSION DEBUG START ===")
	// fmt.Printf("User object to store: %+v\n", user)
	// session.Set("user", user)
	// session.Set("accesstoken", accessToken)
	// //session.Set("user_id", dbUser.ID) // Store database ID in session
	// fmt.Println("✅ session.Set() completed")

	// // Check if it was stored
	// //storedUser := session.Get("user")
	// //fmt.Printf("Immediately after Set - stored user: %+v\n", storedUser)

	// Remove the old state from session
	fmt.Printf("State before delete: %+v\n", session.Get(SessionStateKey))
	session.Delete(SessionStateKey)
	fmt.Printf("State after delete: %+v\n", session.Get(SessionStateKey))

	// // Save the updated session
	// fmt.Println("About to call session.Save()...")
	err = session.Save()
	if err != nil {
		fmt.Printf("❌ SESSION SAVE ERROR: %v\n", err)
		fmt.Printf("Error type: %T\n", err)
		http.Error(c.Writer, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// fmt.Println("✅ session.Save() completed successfully!")

	// // Redirect to /welcome
	// c.Redirect(http.StatusFound, "/welcome")
	// Return JWT instead of storing in session
	c.JSON(http.StatusOK, gin.H{
		"jwt":  jwtToken,
		"user": user,
	})
}

func HandleWelcome(c *gin.Context) {
	source := c.GetString("auth_source")
	fmt.Println("auth source:", source)
	fmt.Println("489")
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	fmt.Println("userId", userID)
	// Lookup user's GitHub token from database
	user, err := helper.Queries.GetUserByID(c, userID.(int64))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	fmt.Fprintf(c.Writer, "<html><body>")
	fmt.Fprintf(c.Writer, "<h1>Welcome, %s</h1>", user.Username)
	if user.Username != "" {
		fmt.Fprintf(c.Writer, "<p>Name: %s</p>", user.Username)
	}
	if *user.Email != "" {
		fmt.Fprintf(c.Writer, "<p>Email: %s</p>", user.Email)
	}
	if *user.AvatarUrl != "" {
		fmt.Fprintf(c.Writer, `<img src="%s" width="100"/>`, *user.AvatarUrl)
	}

	fmt.Fprintf(c.Writer, `<form action="/logout" method="post"><button type="submit">Logout</button></form>`)

	fmt.Fprintf(c.Writer, `
		<h1>Review Repository</h1>
		<form action="/analysis" method="GET">
			<label>Repository URL:</label>
			<p>Please use Http for better speed</p>
			<input type="text" name="repo_url" placeholder="ssh git@github.com/username/repo" required>
			<button type="submit">Submit</button>
		</form>
	`)
	fmt.Fprintf(c.Writer, "</body></html>")
	// Add a logout button that POSTs to /logout
	fmt.Printf("Handling Welcome")
}

func HandleLogout(c *gin.Context) {

	// Retrieve the session for this request
	session := sessions.Default(c)
	// Delete the user entry from session
	session.Delete("user")
	// Optionally clear other session values like state
	session.Clear()
	// Save the session (to update the cookie)
	err := session.Save()
	if err != nil {
		http.Error(c.Writer, "Failed to save session", http.StatusInternalServerError)
	}
	// Redirect to home ("/")
	c.Redirect(http.StatusFound, "/")
	fmt.Printf("Handling Logout")
}

func HandleCloneRepo(c *gin.Context) {
	//this api will clone the repo and it will create a worker pool to get content of each file and send to llm to check if errors are handeld properly or not
	fmt.Printf("229")
	repoURL := ""
	repoURL = c.PostForm("repo_url")
	fmt.Printf("Repository URL: %s\n", repoURL)

	if repoURL == "" {
		repoURL = c.Request.URL.Query().Get("repo_url")
		if repoURL == "" {
			c.String(http.StatusBadRequest, "missing repo_url parameter")
			return
		}
	}

	fmt.Printf("238\n")
	sess := sessions.Default(c)
	accessToken, ok := sess.Get("accesstoken").(string)
	if !ok || accessToken == "" {
		// Fallback: allow Bearer token via Authorization header for API clients (e.g., Postman)
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			accessToken = strings.TrimSpace(authHeader[len("Bearer "):])
		}
		// Optional: allow access_token form field as a secondary fallback
		if accessToken == "" {
			accessToken = c.PostForm("access_token")
		}
		if accessToken == "" {
			c.String(http.StatusUnauthorized, "Access token not found")
			return
		}
	}

	//todo

	fmt.Printf("245\n")
	//todo: clone the repo
	repoName := "test/" + strings.TrimSuffix(path.Base(repoURL), ".git")
	err := helper.CloneRepo(repoURL, repoName, accessToken)
	if err != nil {
		fmt.Printf("Error cloning repo: %v\n", err)
		http.Error(c.Writer, fmt.Sprintf("Failed to clone repository: %v", err), http.StatusInternalServerError)
		return
	}
	c.String(http.StatusOK, "Repository cloned successfully")
}

func HandleAnalysisPage(c *gin.Context) {
	// repo := c.Query("repo")
	repo := c.Query("repo_url")
	if repo == "" {
		http.Error(c.Writer, "missing repo parameter", http.StatusBadRequest)
		return
	}

	html := fmt.Sprintf(`<!doctype html>
<html>
<head><title>Analysis Options</title></head>
<body>
  <h1>Repository: %s</h1>
  <p>Choose what you want to do next:</p>

  <form method="get" action="/static-analysis" style="margin-bottom: 1rem;">
    <input type="hidden" name="repo" value="%s">
    <input type="hidden" name="action" value="static">
    <button type="submit">Run Static Analysis</button>
  </form>
</body>
</html>`, repo, repo)

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

func HandleStaticAnalysis(c *gin.Context) {
	repo := c.PostForm("repo")
	if repo == "" {
		repo = c.Request.URL.Query().Get("repo")
		if repo == "" {
			c.String(http.StatusBadRequest, "missing repo_url parameter")
			return
		}
	}

	fmt.Printf("repo: %s\n", repo)

	repoName := strings.TrimSuffix(path.Base(repo), ".git")

	dir := filepath.Join(".", "test", repoName)
	// Get absolute path
	absDir, err := filepath.Abs(dir)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to get absolute path: %v", err)
		return
	}

	fmt.Printf("Absolute dir: %s\n", absDir)

	// Check if directory exists
	if _, err := os.Stat(absDir); err != nil {
		c.String(http.StatusBadRequest, "repo directory not found: %s", absDir)
		return
	}

	// Prepare command: cd into repo dir and run govulncheck
	cmd := exec.Command("govulncheck", "./...")
	cmd.Dir = absDir
	fmt.Printf("cmd: %s\n", cmd)
	fmt.Printf("cmd.Dir: %s\n", cmd.Dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	exitErr, _ := err.(*exec.ExitError)

	if err != nil {
		if exitErr != nil && exitErr.ExitCode() == 3 {
			// Vulnerabilities found
			c.Data(http.StatusOK, "text/plain; charset=utf-8", stdout.Bytes())
			return
		}

		// error
		c.String(http.StatusInternalServerError, "govulncheck failed:\n%s\n%s", err.Error(), stderr.String())
		return
	}

	c.Data(http.StatusOK, "text/plain; charset=utf-8", stdout.Bytes())
}

func UserData(c *gin.Context) {
	//this api will return the user data from the database
	// sess := sessions.Default(c)
	fmt.Println("489")
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	fmt.Println("userId", userID)
	// Lookup user's GitHub token from database
	dbUser, err := helper.Queries.GetUserByID(c, userID.(int64))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}
	fmt.Println("*dbUser.AccessToken", *dbUser.AccessToken)
	dec, err := helper.DecryptToken(*dbUser.AccessToken)
	if err != nil {
		fmt.Println("not decrypted")
	}

	// Create an OAuth client using the returned token
	client := helper.OauthConfig.Client(c, &oauth2.Token{AccessToken: dec})

	// Call GitHub API to fetch the authenticated user's info
	response, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(c.Writer, "Failed to fetch user data", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		http.Error(c.Writer, "Failed to read user data", http.StatusInternalServerError)
		return
	}
	fmt.Println("body", string(body))

	//lets parse body to interface string map
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		http.Error(c.Writer, "Failed to parse user data", http.StatusInternalServerError)
		return
	}
	fmt.Println("data", data)

	var user models.GitHubUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		http.Error(c.Writer, "Failed to parse user data", http.StatusInternalServerError)
		return
	}
	fmt.Println("user", user)

	c.JSON(http.StatusOK, data)
}

func UserFollowers(c *gin.Context) {
	//this api will return the user data from the database
	// sess := sessions.Default(c)

	// token, ok := sess.Get("accesstoken").(string)
	authHeader := c.GetHeader("Authorization")
	accessToken := ""
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		accessToken = strings.TrimSpace(authHeader[len("Bearer "):])
	}

	perPageStr := c.DefaultQuery("per_page", "2")
	pageStr := c.DefaultQuery("page", "1")

	// Create an OAuth client using the returned token
	client := helper.OauthConfig.Client(c, &oauth2.Token{AccessToken: accessToken})

	// Build GitHub API URL
	baseURL := "https://api.github.com/user/following"

	apiURL := fmt.Sprintf("%s?per_page=%s&page=%s", baseURL, perPageStr, pageStr)

	response, err := client.Get(apiURL)
	if err != nil {
		http.Error(c.Writer, "Failed to fetch followers", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		http.Error(c.Writer, "Failed to read response", http.StatusInternalServerError)
		return
	}

	// Parse list payload
	var items []models.Followers
	if err := json.Unmarshal(body, &items); err != nil {
		http.Error(c.Writer, "Failed to parse followers list", http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"pagination": parseLinkHeader(response.Header.Get("Link")),
		"per_page":   perPageStr,
		"page":       pageStr,
	})
}

// parseLinkHeader extracts pagination links from GitHub's Link header
func parseLinkHeader(linkHeader string) map[string]string {
	fmt.Println("linkHeader", linkHeader)
	result := map[string]string{}
	if linkHeader == "" {
		return result
	}
	parts := strings.Split(linkHeader, ",")
	fmt.Println("parts", parts)
	for _, p := range parts {
		seg := strings.Split(strings.TrimSpace(p), ";")
		if len(seg) < 2 {
			continue
		}
		urlPart := strings.TrimSpace(seg[0])
		relPart := strings.TrimSpace(seg[1])
		if strings.HasPrefix(urlPart, "<") && strings.HasSuffix(urlPart, ">") {
			urlPart = urlPart[1 : len(urlPart)-1]
		}
		if strings.HasPrefix(relPart, "rel=") {
			rel := strings.Trim(relPart[len("rel="):], "\"")
			result[rel] = urlPart
		}
	}
	return result
}
