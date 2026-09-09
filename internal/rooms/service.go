package rooms

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	maxNameLength  = 100
	listLimit      = 100
	slugAttempts   = 5
	slugGroupSizes = "344" // e.g. abc-defg-hij, the shape of a meeting link
)

// slugAlphabet omits vowels and look-alike characters, so a slug read aloud or
// copied by hand is hard to get wrong and cannot spell anything unfortunate.
const slugAlphabet = "bcdfghjkmnpqrstvwxz23456789"

var ErrInvalidName = fmt.Errorf("rooms: name must be 1-%d characters", maxNameLength)

type Service struct {
	store *Store
}

func NewService(store *Store) *Service { return &Service{store: store} }

// Create makes a room with a generated slug.
//
// The slug is the invitation, so it is generated rather than taken from the
// caller: a user-chosen slug would be guessable, and guessing a slug is
// exactly how an uninvited participant would join a call.
func (s *Service) Create(ctx context.Context, createdBy, name string) (Room, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "New room"
	}
	if utf8.RuneCountInString(name) > maxNameLength {
		return Room{}, ErrInvalidName
	}

	// A collision is vanishingly unlikely, but the unique index is the real
	// guarantee; retrying keeps that from surfacing as a 500.
	for attempt := range slugAttempts {
		slug, err := generateSlug()
		if err != nil {
			return Room{}, err
		}

		room, err := s.store.Create(ctx, createdBy, slug, name)
		if err == nil {
			return room, nil
		}
		if !errors.Is(err, ErrSlugTaken) {
			return Room{}, err
		}
		_ = attempt
	}
	return Room{}, errors.New("rooms: could not allocate a unique slug")
}

func (s *Service) BySlug(ctx context.Context, slug string) (Room, error) {
	return s.store.BySlug(ctx, strings.ToLower(strings.TrimSpace(slug)))
}

func (s *Service) List(ctx context.Context) ([]Room, error) {
	return s.store.List(ctx, listLimit)
}

func generateSlug() (string, error) {
	groups := make([]string, 0, len(slugGroupSizes))

	for _, sizeRune := range slugGroupSizes {
		size := int(sizeRune - '0')
		buf := make([]byte, size)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("generate slug: %w", err)
		}
		for i, b := range buf {
			buf[i] = slugAlphabet[int(b)%len(slugAlphabet)]
		}
		groups = append(groups, string(buf))
	}

	return strings.Join(groups, "-"), nil
}
