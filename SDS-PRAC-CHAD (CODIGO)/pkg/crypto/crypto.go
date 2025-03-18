package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// DeriveKey uses Argon2id to derive a symmetric key from the provided password, salt and context.
// The salt is combined with the context and then used in the key derivation.
func DeriveKey(password, salt, context string) ([]byte, error) {
	combinedSalt := []byte(salt + ":" + context)
	// Argon2id parameters:
	// time = 1, memory = 64*1024, parallelism = 4, key length = 32 bytes
	key := argon2.IDKey([]byte(password), combinedSalt, 1, 64*1024, 4, 32)
	return key, nil
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
