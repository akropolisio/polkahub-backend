BEGIN;

ALTER TABLE users RENAME TO users_old;
ALTER INDEX users_token_token_expired_at_idx RENAME TO users_token_token_expired_at_old_idx;
ALTER INDEX users_email_verification_token_key RENAME TO users_email_verification_token_old_key;

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT 'f',
    email_verification_token TEXT,
    token TEXT,
    token_expired_at TIMESTAMPTZ,
    password_reset_token TEXT,
    password_reset_token_expired_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX users_token_token_expired_at_idx ON users USING BTREE (token, token_expired_at);
CREATE UNIQUE INDEX users_email_verification_token_key ON users USING BTREE (email_verification_token);

INSERT INTO users
    SELECT id, login, email, password, email_verified, email_verification_token, token, token_expired_at, null, null, created_at, updated_at
    FROM users_old;

ALTER TABLE user_applications DROP CONSTRAINT user_applications_user_id_fkey;
ALTER TABLE user_projects DROP CONSTRAINT user_projects_user_id_fkey;

ALTER TABLE user_applications ADD CONSTRAINT user_applications_user_id_fkey FOREIGN KEY(user_id) REFERENCES users(id);
ALTER TABLE user_projects ADD CONSTRAINT user_projects_user_id_fkey FOREIGN KEY(user_id) REFERENCES users(id);

DROP TABLE users_old;

COMMIT;
