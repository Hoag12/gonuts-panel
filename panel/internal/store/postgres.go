package store

import (
	"database/sql"
	"time"

	_ "github.com/lib/pq"
)

// postgresSink keeps one durable JSON snapshot of the panel state in a small
// table. It survives redeploys that wipe the service's ephemeral disk.
type postgresSink struct {
	db *sql.DB
}

// NewPostgresSink connects to dsn and prepares the snapshot table.
func NewPostgresSink(dsn string) (Sink, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetConnMaxIdleTime(2 * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS panel_state (
		id integer PRIMARY KEY,
		body bytea NOT NULL,
		saved_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &postgresSink{db: db}, nil
}

// LoadState returns the last snapshot, or ok=false before the first save.
func (p *postgresSink) LoadState() ([]byte, bool, error) {
	var body []byte
	err := p.db.QueryRow(`SELECT body FROM panel_state WHERE id = 1`).Scan(&body)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return body, true, nil
}

// SaveState replaces the snapshot.
func (p *postgresSink) SaveState(body []byte) error {
	_, err := p.db.Exec(`INSERT INTO panel_state (id, body, saved_at)
		VALUES (1, $1, now())
		ON CONFLICT (id) DO UPDATE SET body = EXCLUDED.body, saved_at = now()`, body)
	return err
}

// Close releases the connection pool.
func (p *postgresSink) Close() error { return p.db.Close() }

var _ Sink = (*postgresSink)(nil)
