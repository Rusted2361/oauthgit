package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"oauthgit/helper"
	"oauthgit/models"

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
	//fmt.Println("accessToken", accessToken)

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

	// Store the user info inside the session (now includes database ID)
	//fmt.Println("=== SESSION DEBUG START ===")
	fmt.Printf("User object to store: %+v\n", user)
	session.Set("user", user)
	session.Set("accesstoken", accessToken)
	//session.Set("user_id", dbUser.ID) // Store database ID in session
	fmt.Println("✅ session.Set() completed")

	// Check if it was stored
	//storedUser := session.Get("user")
	//fmt.Printf("Immediately after Set - stored user: %+v\n", storedUser)

	// Remove the old state from session
	fmt.Printf("State before delete: %+v\n", session.Get(SessionStateKey))
	session.Delete(SessionStateKey)
	fmt.Printf("State after delete: %+v\n", session.Get(SessionStateKey))

	// Save the updated session
	fmt.Println("About to call session.Save()...")
	err = session.Save()
	if err != nil {
		fmt.Printf("❌ SESSION SAVE ERROR: %v\n", err)
		fmt.Printf("Error type: %T\n", err)
		http.Error(c.Writer, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("✅ session.Save() completed successfully!")

	// Redirect to /welcome
	c.Redirect(http.StatusFound, "/welcome")
}

func HandleWelcome(c *gin.Context) {
	// Retrieve the session for this request
	session := sessions.Default(c)
	// Read the user object from session
	user, ok := session.Get("user").(models.GitHubUser)
	// If no user is found, redirect to /login
	if !ok {
		http.Redirect(c.Writer, c.Request, "/login", http.StatusFound)
		return
	}

	fmt.Fprintf(c.Writer, "<html><body>")
	fmt.Fprintf(c.Writer, "<h1>Welcome, %s</h1>", user.Login)
	if user.Name != "" {
		fmt.Fprintf(c.Writer, "<p>Name: %s</p>", user.Name)
	}
	if user.Email != "" {
		fmt.Fprintf(c.Writer, "<p>Email: %s</p>", user.Email)
	}
	if user.AvatarURL != "" {
		fmt.Fprintf(c.Writer, `<img src="%s" width="100"/>`, user.AvatarURL)
	}

	fmt.Fprintf(c.Writer, `<form action="/logout" method="post"><button type="submit">Logout</button></form>`)

	fmt.Fprintf(c.Writer, `
		<h1>Review Repository</h1>
		<form action="/ReviewRepo" method="POST">
			<label>Repository URL:</label>
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

func HandleReviewRepo(c *gin.Context) {
	//this api will clone the repo and it will create a worker pool to get content of each file and send to llm to check if errors are handeld properly or not

	repoURL := ""
	if c.Request.Method == "POST" {
		repoURL = c.PostForm("repo_url")
		fmt.Printf("Repository URL: %s\n", repoURL)

		c.String(http.StatusOK, "Repository URL received: %s", repoURL)
		return
	}
	sess := sessions.Default(c)
	accessToken, ok := sess.Get("accesstoken").(string)
	if !ok {
		c.String(http.StatusUnauthorized, "Access token not found")
		return
	}

	//todo: clone the repo
	err := helper.CloneRepo(repoURL, "/", accessToken)
	if err != nil {
		fmt.Printf("Error cloning repo: %v\n", err)
	}

	c.Header("Content-Type", "text/html")

}
