package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

// DeriveKey uses scrypt to derive a symmetric key from the provided password and salt.
// Here, we use the username as the salt.
func DeriveKey(password, salt string) ([]byte, error) {
	// The parameters N, r and p are chosen for a good tradeoff between security and performance.
	return scrypt.Key([]byte(password), []byte(salt), 32768, 8, 1, 32)
}

// Encrypt encrypts the plaintext using AES-GCM with the provided key.
// It returns the nonce concatenated with the ciphertext.
func Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	// Prepend nonce to ciphertext
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts the data using AES-GCM with the provided key.
// It expects the input to be nonce concatenated with ciphertext.
func Decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}
