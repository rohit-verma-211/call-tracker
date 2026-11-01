CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('hr', 'employee')),
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS call_logs (
  id            BIGSERIAL PRIMARY KEY,
  employee_id   INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  phone_number  TEXT NOT NULL,
  contact_name  TEXT,
  direction     TEXT NOT NULL CHECK (direction IN ('OUTGOING', 'INCOMING', 'MISSED', 'REJECTED', 'OTHER')),
  duration_sec  INT NOT NULL DEFAULT 0 CHECK (duration_sec >= 0),
  called_at     TIMESTAMPTZ NOT NULL,
  summary       TEXT,            -- filled later by the AI summary pipeline
  recording_url TEXT,            -- filled later when recordings are added
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (employee_id, phone_number, called_at)
);

CREATE INDEX IF NOT EXISTS idx_calls_employee_time ON call_logs (employee_id, called_at DESC);
CREATE INDEX IF NOT EXISTS idx_calls_time ON call_logs (called_at DESC);
CREATE INDEX IF NOT EXISTS idx_calls_direction ON call_logs (direction);
