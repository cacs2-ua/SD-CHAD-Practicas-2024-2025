package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// DeriveKey uses Argon2id to derive a symmetric key from the provided password, salt and context.
func DeriveKey(password, salt, context string) ([]byte, error) {
	combinedSalt := []byte(salt + ":" + context)
	key := argon2.IDKey([]byte(password), combinedSalt, 1, 64*1024, 4, 32)
	return key, nil
}

// Encrypt encrypts the plaintext using AES-GCM with the provided key.
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
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts the data using AES-GCM with the provided key.
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

// uuidKey is the server symmetric key for UUID encryption (32 bytes exactly).
var uuidKey = []byte("thisis32bytekeyforuuidencrypt!!")

// EncryptUUID encrypts the uuid string using AES-GCM with uuidKey and returns a base64 encoded string.
func EncryptUUID(uuidStr string) (string, error) {
	encrypted, err := Encrypt([]byte(uuidStr), uuidKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptUUID decrypts a base64 encoded string using AES-GCM with uuidKey.
func DecryptUUID(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	decrypted, err := Decrypt(data, uuidKey)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
