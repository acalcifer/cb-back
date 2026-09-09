package database

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationLockID namespaces the advisory lock that serialises migrations. Any
// constant works as long as nothing else in the database uses the same value.
const migrationLockID int64 = 8_147_320_951

// Migrate applies every unapplied migration in filename order, each inside its
// own transaction.
//
// A session-level advisory lock is taken first so that several replicas
// starting at once cannot apply the same file concurrently: the losers block,
// then find the work already recorded and skip it.
func Migrate(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	files, err := migrationFiles()
	if err != nil {
		return err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// Uses context.WithoutCancel so the lock is still released when the
		// caller's context has already been cancelled.
		if _, err := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLockID); err != nil {
			logger.Error("release migration lock failed", "error", err)
		}
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		return err
	}

	for _, name := range files {
		if _, done := applied[name]; done {
			continue
		}
		if err := applyMigration(ctx, conn, name); err != nil {
			return err
		}
		logger.Info("migration applied", "version", name)
	}
	return nil
}

func migrationFiles() ([]string, error) {
	entries, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no migrations embedded")
	}
	sort.Strings(entries)
	return entries, nil
}

func appliedVersions(ctx context.Context, conn *pgxpool.Conn) (map[string]struct{}, error) {
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]struct{})
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		applied[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", err)
	}
	return applied, nil
}

func applyMigration(ctx context.Context, conn *pgxpool.Conn, name string) error {
	body, err := migrationFS.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin %s: %w", name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	if _, err := tx.Exec(ctx, string(body)); err != nil {
		return fmt.Errorf("apply %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
		return fmt.Errorf("record %s: %w", name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit %s: %w", name, err)
	}
	return nil
}
