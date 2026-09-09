package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	ctx := context.Background()
	const password = "correct horse battery staple"

	encoded, err := HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Fatalf("hash is not PHC-encoded argon2id: %q", encoded)
	}
	if strings.Contains(encoded, password) {
		t.Fatal("hash contains the plaintext password")
	}

	match, needsRehash, err := VerifyPassword(ctx, encoded, password)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !match {
		t.Fatal("correct password did not verify")
	}
	if needsRehash {
		t.Fatal("a hash just created should not need rehashing")
	}

	match, _, err = VerifyPassword(ctx, encoded, password+"x")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if match {
		t.Fatal("wrong password verified")
	}
}

func TestHashesAreSalted(t *testing.T) {
	ctx := context.Background()
	const password = "the same password twice"

	first, err := HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	second, err := HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if first == second {
		t.Fatal("identical passwords produced identical hashes; the salt is not random")
	}
}

func TestVerifyDetectsOutdatedParameters(t *testing.T) {
	ctx := context.Background()
	const password = "a sufficiently long password"

	// A hash made with weaker parameters than the current policy.
	weaker := params{memoryKiB: 8 * 1024, iterations: 1, parallelism: 1, saltLength: 16, keyLength: 32}
	saved := argon2Params
	argon2Params = weaker
	encoded, err := HashPassword(ctx, password)
	argon2Params = saved
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	match, needsRehash, err := VerifyPassword(ctx, encoded, password)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !match {
		t.Fatal("password hashed with older parameters did not verify")
	}
	if !needsRehash {
		t.Fatal("outdated parameters were not flagged for rehash")
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	ctx := context.Background()
	tests := map[string]string{
		"empty":            "",
		"not phc":          "just-a-string",
		"wrong algorithm":  "$bcrypt$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
		"missing sections": "$argon2id$v=19$m=19456,t=2,p=1",
		"bad params":       "$argon2id$v=19$m=abc,t=2,p=1$c2FsdA$aGFzaA",
		"bad base64":       "$argon2id$v=19$m=19456,t=2,p=1$!!!!$aGFzaA",
	}

	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			match, _, err := VerifyPassword(ctx, encoded, "whatever")
			if err == nil {
				t.Fatal("expected an error for a malformed hash")
			}
			if match {
				t.Fatal("a malformed hash must never report a match")
			}
			if !errors.Is(err, ErrInvalidHash) && !errors.Is(err, ErrIncompatibleHash) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{"too short", "short", ErrPasswordTooShort},
		{"exactly minimum", strings.Repeat("xk", MinPasswordLength/2), nil},
		{"too long", strings.Repeat("a", MaxPasswordLength+1), ErrPasswordTooLong},
		{"all one repeated letter is blocked", strings.Repeat("a", MinPasswordLength), ErrPasswordNotAllowed},
		{"common password", "password1234", ErrPasswordNotAllowed},
		{"common password mixed case", "Password1234", ErrPasswordNotAllowed},
		{"acceptable", "a reasonable passphrase", nil},
		{"unicode counted by rune", strings.Repeat("é", MinPasswordLength), nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.password)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidatePassword = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	valid := []string{"user@example.com", "  User@Example.COM  ", "a.b+tag@sub.example.co.uk"}
	for _, raw := range valid {
		t.Run("valid/"+raw, func(t *testing.T) {
			got, err := validateEmail(raw)
			if err != nil {
				t.Fatalf("validateEmail(%q) = %v", raw, err)
			}
			if got != strings.ToLower(strings.TrimSpace(raw)) {
				t.Fatalf("email not normalized: %q", got)
			}
		})
	}

	invalid := []string{"", "no-at-sign", "user@", "@example.com", "user@localhost", "Name <user@example.com>", "a@b@c.com"}
	for _, raw := range invalid {
		t.Run("invalid/"+raw, func(t *testing.T) {
			if _, err := validateEmail(raw); !errors.Is(err, ErrInvalidEmail) {
				t.Fatalf("validateEmail(%q) = %v, want ErrInvalidEmail", raw, err)
			}
		})
	}
}
