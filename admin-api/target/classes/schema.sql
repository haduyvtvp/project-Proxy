CREATE TABLE IF NOT EXISTS access_logs (
    id         BIGSERIAL PRIMARY KEY,
    logged_at  TIMESTAMP    NOT NULL,
    client     VARCHAR(100),
    host       VARCHAR(255),
    method     VARCHAR(20),
    result     VARCHAR(20),
    reason     VARCHAR(100),
    raw        TEXT,
    UNIQUE (raw)
);

ALTER TABLE access_logs
    ADD COLUMN IF NOT EXISTS reason VARCHAR(100);

CREATE INDEX IF NOT EXISTS idx_access_logs_time   ON access_logs (logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_logs_host   ON access_logs (host);
CREATE INDEX IF NOT EXISTS idx_access_logs_result ON access_logs (result);