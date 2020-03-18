BEGIN;

ALTER TABLE users DROP COLUMN password_reset_token;
ALTER TABLE users DROP COLUMN password_reset_token_expired_at;

COMMIT;
