// Package store owns the PostgreSQL connection pool and schema migrations.
//
// Queries live next to the domain code that uses them (pgx directly) rather
// than in one generated package: every module owns its SQL, and parallel
// work on modules does not fight over a shared generated file.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

// DB is the shared pool. It is a thin alias so callers can depend on
// store.DB without importing pgxpool directly.
type DB = pgxpool.Pool

// Querier is satisfied by *pgxpool.Pool, pgx.Tx and *pgx.Conn.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// minPoolConns is the pool size used unless the DSN sets pool_max_conns.
const minPoolConns = 16

// Open connects and verifies the connection.
func Open(ctx context.Context, dsn string) (*DB, error) { return OpenWithPassword(ctx, dsn, "") }

// OpenWithPassword is Open with the password kept out of the DSN.
func OpenWithPassword(ctx context.Context, dsn, password string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database dsn: %w", err)
	}
	if password != "" {
		cfg.ConnConfig.Password = password
	}
	// pgxpool defaults to max(4, CPUs) connections, too few for the web
	// API, the agent gateway and the background loops on a small host.
	if !strings.Contains(dsn, "pool_max_conns") && cfg.MaxConns < minPoolConns {
		cfg.MaxConns = minPoolConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending migrations.
func Migrate(ctx context.Context, pool *DB) error {
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	// Downgrades are refused: a database migrated by a newer Olympos has
	// versions this binary does not know.
	known, err := goose.CollectMigrations("migrations", 0, goose.MaxVersion)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	latest, err := known.Last()
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	var applied int64
	err = pool.QueryRow(ctx, `SELECT COALESCE(max(version_id), 0) FROM goose_db_version WHERE is_applied`).Scan(&applied)
	if err != nil && !isUndefinedTable(err) {
		return fmt.Errorf("migrate: read schema version: %w", err)
	}
	if applied > latest.Version {
		return fmt.Errorf("the database schema is at version %d, newer than this olympos-server (%d): downgrades are not supported; "+
			"run the newer version or restore a dump taken before the upgrade", applied, latest.Version)
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// SchemaVersion is the highest applied migration.
func SchemaVersion(ctx context.Context, q Querier) (int64, error) {
	var v int64
	err := q.QueryRow(ctx, `SELECT COALESCE(max(version_id), 0) FROM goose_db_version WHERE is_applied`).Scan(&v)
	return v, err
}

func isUndefinedTable(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "42P01"
}

// Tx runs fn in a transaction, committing on nil error.
func Tx(ctx context.Context, pool *DB, fn func(tx pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ErrNotFound is returned by lookups that match no row.
var ErrNotFound = errors.New("not found")

// NotFound maps pgx.ErrNoRows to ErrNotFound.
func NotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// IsUniqueViolation reports whether err is a unique constraint violation.
func IsUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
