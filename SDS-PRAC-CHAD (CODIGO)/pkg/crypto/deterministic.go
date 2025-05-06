package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

func DeterministicEncrypt(plaintext, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("error creating cipher in DeterministicEncrypt: " + err.Error())
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic("error creating GCM in DeterministicEncrypt: " + err.Error())
	}
	nonce := make([]byte, aesGCM.NonceSize())
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return ciphertext
}

func DeterministicDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
