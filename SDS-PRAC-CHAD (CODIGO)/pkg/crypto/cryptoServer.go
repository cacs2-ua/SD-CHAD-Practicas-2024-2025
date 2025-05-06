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
	return append(nonce, ciphertext...), nil
}

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
