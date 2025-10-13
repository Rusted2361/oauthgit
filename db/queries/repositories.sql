-- name: CreateRepository :one
INSERT INTO repositories (
    github_id,
    user_id,
    full_name,
    owner,
    name,
    is_active
) VALUES (
             $1, $2, $3, $4, $5, $6
         )
    RETURNING *;

-- name: GetRepositoryByID :one
SELECT * FROM repositories
WHERE id = $1;

-- name: GetRepositoryByGithubID :one
SELECT * FROM repositories
WHERE github_id = $1;

-- name: GetRepositoryByFullName :one
SELECT * FROM repositories
WHERE full_name = $1;

-- name: ListRepositoriesByUser :many
SELECT * FROM repositories
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: ListActiveRepositories :many
SELECT * FROM repositories
WHERE is_active = true
ORDER BY created_at DESC;

-- name: UpdateRepositoryStatus :exec
UPDATE repositories
SET
    is_active = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteRepository :exec
DELETE FROM repositories
WHERE id = $1;