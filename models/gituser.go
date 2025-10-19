package models

import "github.com/golang-jwt/jwt/v4"

//todo write structs of any data use during app

type GitHubUser struct {
	Login     string `json:"login"`
	ID        int64  `json:"id"`
	AvatarURL string `json:"avatar_url"`
	Name      string `json:"name"`
	Email     string `json:"email"`
}

type Followers struct {
	Login     string `json:"login"`
	ID        int64  `json:"id"`
	AvatarURL string `json:"avatar_url"`
	UserType  string `json:"type"`
}

type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.StandardClaims
}
