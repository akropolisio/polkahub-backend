CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT 'f',
    email_verification_token TEXT,
    token TEXT,
    token_expired_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX users_token_token_expired_at_idx ON users USING BTREE (token, token_expired_at);
CREATE UNIQUE INDEX users_email_verification_token_key ON users USING BTREE (email_verification_token);
