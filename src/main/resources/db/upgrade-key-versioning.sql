BEGIN;

ALTER TABLE encryption_keys ADD COLUMN IF NOT EXISTS logical_key_id VARCHAR(36);
ALTER TABLE encryption_keys ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
ALTER TABLE encryption_keys ADD COLUMN IF NOT EXISTS current_version BOOLEAN DEFAULT TRUE;
ALTER TABLE encryption_keys ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMP;
ALTER TABLE encryption_keys ADD COLUMN IF NOT EXISTS rotation_reason VARCHAR(500);

UPDATE encryption_keys SET logical_key_id = key_id WHERE logical_key_id IS NULL;
UPDATE encryption_keys SET version = 1 WHERE version IS NULL;
UPDATE encryption_keys SET current_version = TRUE WHERE current_version IS NULL;

ALTER TABLE encryption_keys ALTER COLUMN logical_key_id SET NOT NULL;
ALTER TABLE encryption_keys ALTER COLUMN version SET NOT NULL;
ALTER TABLE encryption_keys ALTER COLUMN current_version SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_encryption_keys_logical_version ON encryption_keys(logical_key_id, version);
CREATE INDEX IF NOT EXISTS idx_logical_key_current ON encryption_keys(logical_key_id, current_version);

COMMIT;