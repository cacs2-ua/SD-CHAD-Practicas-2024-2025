package token

import (
	"crypto/ed25519"
	"time"

	"github.com/golang-jwt/jwt"
)

// PrivateKey is used for signing tokens.
// It must be set by the server on startup.
var PrivateKey ed25519.PrivateKey

// SetPrivateKey assigns the private key to be used for signing tokens.
func SetPrivateKey(key ed25519.PrivateKey) {
	PrivateKey = key
}

// GenerateAccessToken creates an access JWT for the given user UUID.
func GenerateAccessToken(userUUID string) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   userUUID,
		ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
		Issuer:    "tomato-potato-server",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(PrivateKey)
}

// GenerateRefreshToken creates a refresh JWT for the given user UUID.
func GenerateRefreshToken(userUUID string) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   userUUID,
		ExpiresAt: time.Now().Add(31 * 24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Issuer:    "tomato-potato-server",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(PrivateKey)
}
