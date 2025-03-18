package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
)

// uuidAESKey will hold the AES key for UUID encryption.
var uuidAESKey []byte

// init loads the AES key from keys/uuid.key. The key must be 32 bytes long.
func init() {
	keyPath := filepath.Join("keys", "uuid.key")
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(fmt.Sprintf("Error reading AES key from %s: %v", keyPath, err))
	}
	if len(key) != 32 {
		panic("AES key must be 32 bytes long")
	}
	uuidAESKey = key
}

// EncryptUUID encrypts the given UUID string using AES-GCM with the loaded AES key.
// It returns a base64 encoded string.
func EncryptUUID(uuidStr string) (string, error) {
	block, err := aes.NewCipher(uuidAESKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nil, nonce, []byte(uuidStr), nil)
	encrypted := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptUUID decrypts a base64 encoded string using AES-GCM with the loaded AES key.
func DecryptUUID(ciphertextBase64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(uuidAESKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}
