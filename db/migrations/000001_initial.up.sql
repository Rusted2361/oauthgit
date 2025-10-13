-- Create users table FIRST (referenced by repositories)
CREATE TABLE IF NOT EXISTS users (
     id BIGSERIAL PRIMARY KEY,
     github_id BIGINT UNIQUE NOT NULL,
     username VARCHAR(255) NOT NULL,
     email VARCHAR(255),
     avatar_url TEXT,
     access_token TEXT,
     created_at TIMESTAMPTZ DEFAULT NOW(),
     updated_at TIMESTAMPTZ DEFAULT NOW()
);
-- Create repositories table (now with user_id foreign key)
CREATE TABLE IF NOT EXISTS repositories (
    id BIGSERIAL PRIMARY KEY,
    github_id BIGINT UNIQUE NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    full_name VARCHAR(255) NOT NULL,
    owner VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create pull_requests table
CREATE TABLE IF NOT EXISTS pull_requests (
     id BIGSERIAL PRIMARY KEY,
     github_id BIGINT UNIQUE NOT NULL,
     repository_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
     pr_number INTEGER NOT NULL,
     title TEXT,
     author VARCHAR(255),
     status VARCHAR(50) DEFAULT 'open',
     base_branch VARCHAR(255),
     head_branch VARCHAR(255),
     reviewed_at TIMESTAMPTZ,
     created_at TIMESTAMPTZ DEFAULT NOW(),
     updated_at TIMESTAMPTZ DEFAULT NOW(),
     CONSTRAINT unique_repo_pr_number UNIQUE(repository_id, pr_number)
);

-- Create review_comments table
CREATE TABLE IF NOT EXISTS review_comments (
   id BIGSERIAL PRIMARY KEY,
   pr_id BIGINT NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
   github_comment_id BIGINT,
   file_path TEXT,
   line_number INTEGER,
   comment TEXT NOT NULL,
   severity VARCHAR(20) DEFAULT 'info',
   posted BOOLEAN DEFAULT false,
   posted_at TIMESTAMPTZ,
   created_at TIMESTAMPTZ DEFAULT NOW()
);