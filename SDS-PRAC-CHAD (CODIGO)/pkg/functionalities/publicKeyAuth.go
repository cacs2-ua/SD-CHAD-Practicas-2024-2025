package functionalities

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	pcrypto "prac/pkg/crypto"
	"prac/pkg/store"
)

// AuthKeyData holds the auth key information.
type AuthKeyData struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

// nonceInfo stores the nonce challenge and its timestamp.
type nonceInfo struct {
	Nonce     string
	Timestamp time.Time
}

var (
	nonceMap = make(map[string]nonceInfo)
	nonceMu  sync.Mutex
)

// GenerateAuthKeyPair generates an RSA key pair for public key authentication.
// It saves the private key in keys/users-auth/<username>/private.pem and the public key in keys/users-auth/<username>/public.pem.
// The public key is then encrypted and stored in the DB bucket "auth_public_keys" using hash(email) as key.
func GenerateAuthKeyPair(db store.Store, username, email string) error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("error generating RSA key pair: %v", err)
	}
	pubKey := &privKey.PublicKey

	// Encode private key to PEM
	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	// Encode public key to PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("error marshaling public key: %v", err)
	}
	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Save private key to file: keys/users-auth/<username>/private.pem
	dirPath := filepath.Join("keys", "users-auth", username)
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return fmt.Errorf("error creating auth keys directory: %v", err)
	}
	privKeyPath := filepath.Join(dirPath, "private.pem")
	if err := ioutil.WriteFile(privKeyPath, privPem, 0600); err != nil {
		return fmt.Errorf("error writing private key: %v", err)
	}
	// Save public key to file: keys/users-auth/<username>/public.pem
	pubKeyPath := filepath.Join(dirPath, "public.pem")
	if err := ioutil.WriteFile(pubKeyPath, pubPem, 0644); err != nil {
		return fmt.Errorf("error writing public key: %v", err)
	}

	// Prepare auth key data to store in DB
	authData := AuthKeyData{
		Username:  username,
		PublicKey: string(pubPem),
	}
	authDataBytes, err := json.Marshal(authData)
	if err != nil {
		return fmt.Errorf("error marshaling auth key data: %v", err)
	}
	// Encrypt the auth key data using server encryption
	encryptedData, err := pcrypto.EncryptServer(authDataBytes)
	if err != nil {
		return fmt.Errorf("error encrypting auth key data: %v", err)
	}
	// Store in DB bucket "auth_public_keys" with key = HashBytes(email)
	if err := db.Put("auth_public_keys", store.HashBytes([]byte(email)), encryptedData); err != nil {
		return fmt.Errorf("error storing auth public key in DB: %v", err)
	}
	return nil
}

// InitiatePublicKeyLogin retrieves the auth public key data for the given email,
// generates a nonce challenge, stores it, and returns the nonce and username.
func InitiatePublicKeyLogin(db store.Store, email string) (string, string, error) {
	encryptedData, err := db.Get("auth_public_keys", store.HashBytes([]byte(email)))
	if err != nil {
		return "", "", errors.New("auth public key not found")
	}
	decryptedData, err := pcrypto.DecryptServer(encryptedData)
	if err != nil {
		return "", "", fmt.Errorf("error decrypting auth key data: %v", err)
	}
	var authData AuthKeyData
	if err := json.Unmarshal(decryptedData, &authData); err != nil {
		return "", "", fmt.Errorf("error unmarshaling auth key data: %v", err)
	}
	// Generate nonce
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", fmt.Errorf("error generating nonce: %v", err)
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	nonceMu.Lock()
	nonceMap[email] = nonceInfo{
		Nonce:     nonce,
		Timestamp: time.Now(),
	}
	nonceMu.Unlock()
	return nonce, authData.Username, nil
}

// VerifyPublicKeyLogin verifies the signature of the challenge for the given email.
// If the signature is valid, it retrieves the user's UUID and generates tokens.
func VerifyPublicKeyLogin(db store.Store, email string, signatureB64 string) (string, string, error) {
	nonceMu.Lock()
	nInfo, exists := nonceMap[email]
	if !exists {
		nonceMu.Unlock()
		return "", "", errors.New("no challenge found for this email")
	}
	if time.Since(nInfo.Timestamp) > 5*time.Minute {
		delete(nonceMap, email)
		nonceMu.Unlock()
		return "", "", errors.New("challenge expired")
	}
	delete(nonceMap, email)
	nonceMu.Unlock()

	encryptedData, err := db.Get("auth_public_keys", store.HashBytes([]byte(email)))
	if err != nil {
		return "", "", errors.New("auth public key not found")
	}
	decryptedData, err := pcrypto.DecryptServer(encryptedData)
	if err != nil {
		return "", "", fmt.Errorf("error decrypting auth key data: %v", err)
	}
	var authData AuthKeyData
	if err := json.Unmarshal(decryptedData, &authData); err != nil {
		return "", "", fmt.Errorf("error unmarshaling auth key data: %v", err)
	}
	block, _ := pem.Decode([]byte(authData.PublicKey))
	if block == nil {
		return "", "", errors.New("failed to parse public key PEM")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("error parsing public key: %v", err)
	}
	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return "", "", errors.New("public key is not RSA")
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return "", "", fmt.Errorf("error decoding signature: %v", err)
	}
	hash := sha256.Sum256([]byte(nInfo.Nonce))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature); err != nil {
		return "", "", errors.New("signature verification failed")
	}
	// Retrieve the user's encrypted UUID from the bucket "cheese_auth_uuid" using hash(email)
	encryptedUUID, err := db.Get("cheese_auth_uuid", store.HashBytes([]byte(email)))
	if err != nil {
		return "", "", errors.New("user not found for public key login")
	}
	userUUID, err := pcrypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return "", "", fmt.Errorf("error decrypting user UUID: %v", err)
	}
	// Generate tokens (here using placeholder functions; replace with actual token generation as needed)
	accessToken, err := GenerateAccessToken(userUUID)
	if err != nil {
		return "", "", fmt.Errorf("error generating access token: %v", err)
	}
	refreshToken, err := GenerateRefreshToken(userUUID)
	if err != nil {
		return "", "", fmt.Errorf("error generating refresh token: %v", err)
	}
	return accessToken, refreshToken, nil
}

// LoadAuthPrivateKey loads the auth private key from keys/users-auth/<username>/private.pem.
func LoadAuthPrivateKey(username string) (*rsa.PrivateKey, error) {
	keyPath := filepath.Join("keys", "users-auth", username, "private.pem")
	data, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading auth private key: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse PEM block for auth private key")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing auth private key: %v", err)
	}
	return privKey, nil
}

// Placeholder token generation functions; replace with actual implementations.
func GenerateAccessToken(userUUID string) (string, error) {
	return "accessToken_for_" + userUUID, nil
}

func GenerateRefreshToken(userUUID string) (string, error) {
	return "refreshToken_for_" + userUUID, nil
}
