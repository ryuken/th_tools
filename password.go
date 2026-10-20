package th_tools

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

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
