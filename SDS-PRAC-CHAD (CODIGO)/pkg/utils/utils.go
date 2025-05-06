package utils

import (
	"encoding/hex"
	"fmt"
	"prac/pkg/crypto"
	"prac/pkg/store"
)

const (
	bucketAuthUsernameEmail = "cheese_auth_username_email"
	bucketAuthUUID          = "cheese_auth_uuid"
)

func GetHashedUUIDFromUsername(db store.Store, username string) (string, error) {
	hashedEmail, err := db.Get(bucketAuthUsernameEmail, store.HashBytes([]byte(username)))
	if err != nil {
		return "", fmt.Errorf("username not found: %v", err)
	}
	encryptedUUID, err := db.Get(bucketAuthUUID, hashedEmail)
	if err != nil {
		return "", fmt.Errorf("UUID not found: %v", err)
	}
	decryptedUUID, err := crypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return "", fmt.Errorf("error decrypting UUID: %v", err)
	}
	hashedUUID := store.HashBytes([]byte(decryptedUUID))
	return hex.EncodeToString(hashedUUID), nil
}

func GetEncryptedHashedUUIDFromUsername(db store.Store, username string) (string, error) {
	hashedUUIDHex, err := GetHashedUUIDFromUsername(db, username)
	if err != nil {
		return "", fmt.Errorf("error obtaining hashed UUID: %v", err)
	}
	hashedUUIDBytes, err := hex.DecodeString(hashedUUIDHex)
	if err != nil {
		return "", fmt.Errorf("error decoding hashed UUID: %v", err)
	}
	encrypted, err := db.Get("cheese_auth_cipher_hashed_uuid", hashedUUIDBytes)
	if err != nil {
		return "", fmt.Errorf("error retrieving encrypted UUID: %v", err)
	}
	return string(encrypted), nil
}
