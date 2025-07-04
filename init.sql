CREATE TABLE IF NOT EXISTS refresh_tokens (
                                              user_guid VARCHAR(36) PRIMARY KEY,
    token_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
    );

CREATE TABLE IF NOT EXISTS revoked_tokens (
                                              token TEXT PRIMARY KEY,
                                              expires_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens (expires_at);

CREATE TABLE IF NOT EXISTS sessions (
                                        user_guid VARCHAR(36) PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
    );