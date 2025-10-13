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
-- Create index on username for faster lookups
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_github_id ON users(github_id);

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
-- Create index on full_name for faster lookups
CREATE INDEX idx_repositories_full_name ON repositories(full_name);
CREATE INDEX idx_repositories_is_active ON repositories(is_active);
CREATE INDEX idx_repositories_user_id ON repositories(user_id);
