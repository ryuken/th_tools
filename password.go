package th_tools

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// dummyHash is compared against when no account matches, so a login for an
// unknown email takes as long as one with a wrong password
const dummyHash = "$2a$10$WuGvpZrKQRHcy8/wc.6k6eUPaTaU5kGJVTJ6GbwnjG7vpTKzxNRdu"

// rejectPassword spends the same time as checking a real bcrypt hash
func rejectPassword(password string) {
	bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
}

// HashPassword returns a bcrypt hash of password
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// CheckPassword reports whether password matches hash. Hashes stored before
// the switch to bcrypt are unsalted SHA-512 hex digests; rehash is true when
// such a hash matched, so the caller can upgrade it to bcrypt.
func CheckPassword(hash string, password string) (ok bool, rehash bool) {
	if strings.HasPrefix(hash, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, false
	}

	sum := sha512.Sum512([]byte(password))
	legacy := hex.EncodeToString(sum[:])
	ok = subtle.ConstantTimeCompare([]byte(hash), []byte(legacy)) == 1

	return ok, ok
}
