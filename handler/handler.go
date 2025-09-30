package handler

import (
	"fmt"
	"net/http"
	"oauthgit/helper"
	"oauthgit/models"

	"golang.org/x/oauth2"
)

func HandleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<html><body>"+
		"<h1>GitHub OAuth Demo</h1>"+
		`<a href="/login">Login with GitHub</a>`+
		"</body></html>")
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	// create state and store in session
	state, err := helper.GenerateState()
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}
	sess, _ := models.Store.Get(r, models.SessionName)
	sess.Values[models.SessionStateKey] = state
	if err := sess.Save(r, w); err != nil {
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}
	url := models.OauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, _ := models.Store.Get(r, models.SessionName)

	// verify state
	stored, ok := sess.Values[models.SessionStateKey].(string)
	if !ok || stored == "" {
		http.Error(w, "state missing in session", http.StatusBadRequest)
		return
	}
	queryState := r.URL.Query().Get("state")
	if queryState == "" || queryState != stored {
		http.Error(w, "invalid state parameter", http.StatusBadRequest)
		return
	}
	// exchanged code for token
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code not found", http.StatusBadRequest)
		return
	}
	token, err := models.OauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// create OAuth2 client and fetch user
	client := models.OauthConfig.Client(ctx, token)
	user, err := helper.FetchGitHubUser(client)
	if err != nil {
		http.Error(w, "failed to fetch user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// try fetch email if missing
	if user.Email == "" {
		if email, eerr := helper.FetchPrimaryEmail(client); eerr == nil {
			user.Email = email
		}
	}

	// Save user into session (simple example)
	sess.Values[models.SessionUserKey] = user
	delete(sess.Values, models.SessionStateKey) // remove state
	if err := sess.Save(r, w); err != nil {
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/welcome", http.StatusFound)
}

func HandleWelcome(w http.ResponseWriter, r *http.Request) {
	sess, _ := models.Store.Get(r, models.SessionName)
	u, ok := sess.Values[models.SessionUserKey].(models.GitHubUser)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	fmt.Fprintf(w, "<html><body>")
	fmt.Fprintf(w, "<h1>Welcome, %s</h1>", u.Login)
	if u.Name != "" {
		fmt.Fprintf(w, "<p>Name: %s</p>", u.Name)
	}
	if u.Email != "" {
		fmt.Fprintf(w, "<p>Email: %s</p>", u.Email)
	}
	if u.AvatarURL != "" {
		fmt.Fprintf(w, `<img src="%s" width="100"/>`, u.AvatarURL)
	}
	fmt.Fprintf(w, `<form action="/logout" method="post"><button type="submit">Logout</button></form>`)
	fmt.Fprintf(w, "</body></html>")
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := models.Store.Get(r, models.SessionName)
	delete(sess.Values, models.SessionUserKey)
	_ = sess.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}
