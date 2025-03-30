package utils

import (
	"encoding/hex"
	"fmt"
	"prac/pkg/crypto"
	"prac/pkg/store"
)

// Bucket names used in registration.
const (
	bucketAuthUsernameEmail = "cheese_auth_username_email"
	bucketAuthUUID          = "cheese_auth_uuid"
)

// GetHashedUUIDFromUsername retrieves the hashed UUID from the database using the username.
// It looks up the hashed email from bucketAuthUsernameEmail using the hash of the username,
// then uses that hashed email to get the encrypted UUID from bucketAuthUUID,
// decrypts the UUID, and returns the hash (in hexadecimal) of the decrypted UUID.
func GetHashedUUIDFromUsername(db store.Store, username string) (string, error) {
	// Get hashed email from bucketAuthUsernameEmail using key = HashBytes(username)
	hashedEmail, err := db.Get(bucketAuthUsernameEmail, store.HashBytes([]byte(username)))
	if err != nil {
		return "", fmt.Errorf("username not found: %v", err)
	}
	// Get encrypted UUID from bucketAuthUUID using the hashed email as key.
	encryptedUUID, err := db.Get(bucketAuthUUID, hashedEmail)
	if err != nil {
		return "", fmt.Errorf("UUID not found: %v", err)
	}
	// Decrypt UUID using pcrypto.DecryptUUID.
	decryptedUUID, err := crypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return "", fmt.Errorf("error decrypting UUID: %v", err)
	}
	// Hash the decrypted UUID.
	hashedUUID := store.HashBytes([]byte(decryptedUUID))
	return hex.EncodeToString(hashedUUID), nil
}

// GetEncryptedUUIDFromUsername obtains the encrypted version of the hashed UUID for a user.
// It first gets the hashed UUID (hex-encoded) using GetHashedUUIDFromUsername, decodes it,
// and then retrieves from the "cheese_auth_cypher_uuid" bucket the stored encrypted value.
func GetEncryptedUUIDFromUsername(db store.Store, username string) (string, error) {
	// Get the hashed UUID (hex encoded) using the existing function.
	hashedUUIDHex, err := GetHashedUUIDFromUsername(db, username)
	if err != nil {
		return "", fmt.Errorf("error obtaining hashed UUID: %v", err)
	}
	// Decode the hex string to raw bytes.
	hashedUUIDBytes, err := hex.DecodeString(hashedUUIDHex)
	if err != nil {
		return "", fmt.Errorf("error decoding hashed UUID: %v", err)
	}
	// Retrieve the encrypted hashed UUID from the new bucket.
	encrypted, err := db.Get("cheese_auth_cypher_uuid", hashedUUIDBytes)
	if err != nil {
		return "", fmt.Errorf("error retrieving encrypted UUID: %v", err)
	}
	return string(encrypted), nil
}
