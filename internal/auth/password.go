// Package auth implements registration, login, session management and the
// middleware that guards authenticated endpoints.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	// MinPasswordLength follows NIST SP 800-63B: length is what defends
	// against guessing, so there are no composition rules to work around.
	MinPasswordLength = 12
	// MaxPasswordLength bounds the work a single request can ask for. Argon2
	// cost is dominated by its parameters, but hashing an unbounded body is
	// still free CPU for an attacker.
	MaxPasswordLength = 128
)

// argon2Params are the OWASP-recommended Argon2id settings (19 MiB, 2
// iterations, 1 lane). Memory is deliberately modest: each concurrent login
// holds this much RAM, so raising it trades login throughput for resistance.
var argon2Params = params{
	memoryKiB:   19 * 1024,
	iterations:  2,
	parallelism: 1,
	saltLength:  16,
	keyLength:   32,
}

type params struct {
	memoryKiB   uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// hashSlots bounds how many Argon2 hashes run at once. Without it, a burst of
// login attempts multiplies memoryKiB by the number of in-flight requests and
// can push the process into the OOM killer — a cheap denial of service.
var hashSlots = make(chan struct{}, max(2, runtime.NumCPU()))

var (
	ErrInvalidHash        = errors.New("auth: malformed password hash")
	ErrIncompatibleHash   = errors.New("auth: unsupported password hash algorithm")
	ErrPasswordTooShort   = fmt.Errorf("auth: password must be at least %d characters", MinPasswordLength)
	ErrPasswordTooLong    = fmt.Errorf("auth: password must be at most %d characters", MaxPasswordLength)
	ErrPasswordNotAllowed = errors.New("auth: password is too easily guessed")
)

// ValidatePassword enforces the policy before any hashing happens.
func ValidatePassword(password string) error {
	length := utf8.RuneCountInString(password)
	switch {
	case length < MinPasswordLength:
		return ErrPasswordTooShort
	case length > MaxPasswordLength:
		return ErrPasswordTooLong
	}
	if isCommonPassword(password) {
		return ErrPasswordNotAllowed
	}
	return nil
}

// HashPassword returns a PHC-encoded Argon2id hash:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
//
// Parameters are stored with the hash so they can be increased later and old
// hashes upgraded on next login rather than invalidated.
func HashPassword(ctx context.Context, password string) (string, error) {
	salt := make([]byte, argon2Params.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key, err := deriveKey(ctx, password, salt, argon2Params)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Params.memoryKiB, argon2Params.iterations, argon2Params.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether the password matches, and whether the stored
// hash used weaker parameters than the current policy and should be replaced.
//
// The comparison is constant-time so a timing signal cannot reveal how much of
// a candidate hash was correct.
func VerifyPassword(ctx context.Context, encoded, password string) (match bool, needsRehash bool, err error) {
	stored, salt, key, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}

	candidate, err := deriveKey(ctx, password, salt, stored)
	if err != nil {
		return false, false, err
	}

	if subtle.ConstantTimeCompare(key, candidate) != 1 {
		return false, false, nil
	}
	return true, stored != argon2Params, nil
}

// dummySalt is a fixed salt used only by DummyVerify. It never protects a
// real credential, so a constant is fine.
var dummySalt = []byte("cb-back-timing-eq")

// DummyVerify performs exactly the work of a real verification and discards
// the result. Call it when no account exists, so that response time does not
// reveal which email addresses are registered.
func DummyVerify(ctx context.Context, password string) {
	key, err := deriveKey(ctx, password, dummySalt, argon2Params)
	if err != nil {
		return
	}
	// Keep the comparison too, so both paths do identical work.
	subtle.ConstantTimeCompare(key, key)
}

func deriveKey(ctx context.Context, password string, salt []byte, p params) ([]byte, error) {
	select {
	case hashSlots <- struct{}{}:
		defer func() { <-hashSlots }()
	case <-ctx.Done():
		return nil, fmt.Errorf("hash password: %w", ctx.Err())
	}

	return argon2.IDKey([]byte(password), salt, p.iterations, p.memoryKiB, p.parallelism, p.keyLength), nil
}

func decodeHash(encoded string) (p params, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return p, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return p, nil, nil, ErrIncompatibleHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return p, nil, nil, ErrIncompatibleHash
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memoryKiB, &p.iterations, &p.parallelism); err != nil {
		return p, nil, nil, ErrInvalidHash
	}

	if salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if key, err = base64.RawStdEncoding.Strict().DecodeString(parts[5]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if len(salt) == 0 || len(key) == 0 {
		return p, nil, nil, ErrInvalidHash
	}

	p.saltLength = uint32(len(salt))
	p.keyLength = uint32(len(key))
	return p, salt, key, nil
}
