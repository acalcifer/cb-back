// Package rooms owns room records and the HTTP surface for creating and
// listing them.
package rooms

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const uniqueViolation = "23505"

var (
	ErrNotFound  = errors.New("rooms: room not found")
	ErrSlugTaken = errors.New("rooms: slug already in use")
)

type Room struct {
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	Name      string `json:"name"`
	CreatedBy string `json:"created_by"`
	// CreatedByName is shown in the public directory so a room has a
	// recognisable owner without exposing the creator's email address.
	CreatedByName string    `json:"created_by_name,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) Create(ctx context.Context, createdBy, slug, name string) (Room, error) {
	var r Room
	err := s.pool.QueryRow(ctx, `
		INSERT INTO rooms (slug, name, created_by)
		VALUES ($1, $2, $3)
		RETURNING id::text, slug, name, created_by::text, created_at`,
		slug, name, createdBy,
	).Scan(&r.ID, &r.Slug, &r.Name, &r.CreatedBy, &r.CreatedAt)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return Room{}, ErrSlugTaken
		}
		return Room{}, fmt.Errorf("insert room: %w", err)
	}
	return r, nil
}

func (s *Store) BySlug(ctx context.Context, slug string) (Room, error) {
	var r Room
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, slug, name, created_by::text, created_at
		FROM rooms WHERE slug = $1`, slug,
	).Scan(&r.ID, &r.Slug, &r.Name, &r.CreatedBy, &r.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return Room{}, ErrNotFound
	}
	if err != nil {
		return Room{}, fmt.Errorf("select room: %w", err)
	}
	return r, nil
}

// DeleteBySlug removes a room. Reports ErrNotFound when nothing matched, so a
// repeated delete is a 404 rather than a silent success.
func (s *Store) DeleteBySlug(ctx context.Context, slug string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM rooms WHERE slug = $1`, slug)
	if err != nil {
		return fmt.Errorf("delete room: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns the public room directory, newest first.
//
// Every room is visible to every signed-in user: the directory is how someone
// finds a call to join. The creator's display name travels with each row so the
// list is readable without a second lookup, but their email never does.
func (s *Store) List(ctx context.Context, limit int) ([]Room, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.id::text, r.slug, r.name, r.created_by::text, u.display_name, r.created_at
		FROM rooms r
		JOIN users u ON u.id = r.created_by
		ORDER BY r.created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("select rooms: %w", err)
	}
	defer rows.Close()

	// Non-nil so an empty result encodes as [] rather than null.
	list := make([]Room, 0)
	for rows.Next() {
		var r Room
		if err := rows.Scan(&r.ID, &r.Slug, &r.Name, &r.CreatedBy, &r.CreatedByName, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan room: %w", err)
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rooms: %w", err)
	}
	return list, nil
}
