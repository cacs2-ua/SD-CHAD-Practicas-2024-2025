package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
)

// serverKey will hold the key for server data encryption.
// The key is loaded from keys/tomato_server.key and must be 32 bytes long.
var serverKey []byte

func init() {
	keyPath := filepath.Join("keys", "tomato_server.key")
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(fmt.Sprintf("Error reading server key from %s: %v", keyPath, err))
	}
	if len(key) != 32 {
		panic("Server key must be 32 bytes long")
	}
	serverKey = key
}

// EncryptServer encrypts the plaintext using AES-GCM-256 with the server key.
// It returns the nonce concatenated with the ciphertext.
func EncryptServer(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(serverKey)
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

// DecryptServer decrypts the data using AES-GCM-256 with the server key.
// It expects the input to be nonce concatenated with the ciphertext.
func DecryptServer(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(serverKey)
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
