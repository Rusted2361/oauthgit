-- name: CreateUser :one
INSERT INTO users (
    github_id,
    username,
    email,
    avatar_url,
    access_token
) VALUES (
             $1, $2, $3, $4, $5
         )
    RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1;

-- name: GetUserByGithubID :one
SELECT * FROM users
WHERE github_id = $1;

-- name: GetUserByUsername :one
SELECT * FROM users
WHERE username = $1;

-- name: UpdateUser :one
UPDATE users
SET
    username = $2,
    email = $3,
    avatar_url = $4,
    access_token = $5,
    updated_at = NOW()
WHERE id = $1
    RETURNING *;

-- name: UpdateUserToken :exec
UPDATE users
SET
    access_token = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY created_at DESC
    LIMIT $1 OFFSET $2;