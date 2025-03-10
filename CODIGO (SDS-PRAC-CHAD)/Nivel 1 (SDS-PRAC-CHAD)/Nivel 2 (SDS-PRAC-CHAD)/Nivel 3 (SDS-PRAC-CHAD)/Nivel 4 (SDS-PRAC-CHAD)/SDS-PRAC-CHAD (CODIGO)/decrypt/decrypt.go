package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"prac/pkg/crypto"
)

func main() {
	// This is the base64-encoded ciphertext you provided.
	ciphertextBase64 := "7844boamPzW6V+gAyUlzuMpDJCJN0waXdDOsk9C4zqt3P+g4Bg5/suQ="

	// Decode the base64 string to get the encrypted data (nonce + ciphertext).
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		log.Fatalf("Error decoding base64: %v", err)
	}

	// Replace these with the actual username and password used during encryption.
	username := "crisCHAD"
	password := "crisCHAD" // Use the same password provided during encryption.

	// Derive the encryption key from the password and username.
	key, err := crypto.DeriveKey(password, username)
	if err != nil {
		log.Fatalf("Error deriving key: %v", err)
	}

	// Decrypt the data.
	plaintext, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		log.Fatalf("Error decrypting data: %v", err)
	}

	fmt.Println("Decrypted plaintext:", string(plaintext))
}
