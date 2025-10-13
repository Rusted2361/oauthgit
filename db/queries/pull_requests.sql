-- name: CreatePullRequest :one
INSERT INTO pull_requests (
    github_id,
    repository_id,
    pr_number,
    title,
    author,
    status,
    base_branch,
    head_branch
) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8
         )
    RETURNING *;

-- name: GetPullRequestByID :one
SELECT * FROM pull_requests
WHERE id = $1;

-- name: GetPullRequestByGithubID :one
SELECT * FROM pull_requests
WHERE github_id = $1;

-- name: GetPullRequestByRepoAndNumber :one
SELECT * FROM pull_requests
WHERE repository_id = $1 AND pr_number = $2;

-- name: ListPullRequestsByRepository :many
SELECT * FROM pull_requests
WHERE repository_id = $1
ORDER BY created_at DESC
    LIMIT $2 OFFSET $3;

-- name: ListUnreviewedPullRequests :many
SELECT * FROM pull_requests
WHERE repository_id = $1
  AND status = 'open'
  AND reviewed_at IS NULL
ORDER BY created_at ASC;

-- name: MarkPullRequestReviewed :exec
UPDATE pull_requests
SET
    reviewed_at = NOW(),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdatePullRequestStatus :exec
UPDATE pull_requests
SET
    status = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: DeletePullRequest :exec
DELETE FROM pull_requests
WHERE id = $1;