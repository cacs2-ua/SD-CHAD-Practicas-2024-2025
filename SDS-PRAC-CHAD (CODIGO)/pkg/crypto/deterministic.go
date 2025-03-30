package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

// DeterministicEncrypt encrypts the plaintext deterministically using AES-256 GCM
// with a fixed nonce (all zeros). The key parameter is the server key.
func DeterministicEncrypt(plaintext, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("error creating cipher in DeterministicEncrypt: " + err.Error())
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic("error creating GCM in DeterministicEncrypt: " + err.Error())
	}
	nonce := make([]byte, aesGCM.NonceSize()) // fixed nonce: all zeros
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return ciphertext
}

// DeterministicDecrypt decrypts the ciphertext using AES-256 GCM with the fixed nonce.
// It returns the original plaintext.
func DeterministicDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize()) // fixed nonce: all zeros
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
