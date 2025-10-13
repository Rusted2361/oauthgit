-- name: CreateReviewComment :one
INSERT INTO review_comments (
    pr_id,
    file_path,
    line_number,
    comment,
    severity
) VALUES (
             $1, $2, $3, $4, $5
         )
    RETURNING *;

-- name: GetReviewCommentByID :one
SELECT * FROM review_comments
WHERE id = $1;

-- name: ListReviewCommentsByPR :many
SELECT * FROM review_comments
WHERE pr_id = $1
ORDER BY created_at DESC;

-- name: ListUnpostedComments :many
SELECT * FROM review_comments
WHERE pr_id = $1 AND posted = false
ORDER BY severity DESC, created_at ASC;

-- name: MarkCommentAsPosted :exec
UPDATE review_comments
SET
    posted = true,
    posted_at = NOW(),
    github_comment_id = $2
WHERE id = $1;

-- name: DeleteReviewComment :exec
DELETE FROM review_comments
WHERE id = $1;

-- name: CountCommentsByPR :one
SELECT COUNT(*) FROM review_comments
WHERE pr_id = $1;

-- name: CountUnpostedComments :one
SELECT COUNT(*) FROM review_comments
WHERE pr_id = $1 AND posted = false;