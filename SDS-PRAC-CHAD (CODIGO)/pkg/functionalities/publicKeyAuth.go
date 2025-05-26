package functionalities

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	"golang.org/x/crypto/sha3"

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
	"prac/pkg/token"
)

const bucketAuthUUID = "cheese_auth_uuid"

type AuthKeyData struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

type nonceInfo struct {
	Nonce     string
	Timestamp time.Time
}

var (
	nonceMap = make(map[string]nonceInfo)
	nonceMu  sync.Mutex
)

func GenerateAuthKeyPair(db store.Store, username, userUUID string) error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("error generating RSA key pair: %v", err)
	}
	pubKey := &privKey.PublicKey

	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("error marshaling public key: %v", err)
	}
	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	})

	dirPath := filepath.Join("keys", "users-auth", username)
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return fmt.Errorf("error creating auth keys directory: %v", err)
	}
	privKeyPath := filepath.Join(dirPath, "private.pem")
	if err := ioutil.WriteFile(privKeyPath, privPem, 0600); err != nil {
		return fmt.Errorf("error writing private key: %v", err)
	}

	pubKeyPath := filepath.Join(dirPath, "public.pem")
	if err := ioutil.WriteFile(pubKeyPath, pubPem, 0644); err != nil {
		return fmt.Errorf("error writing public key: %v", err)
	}

	authData := AuthKeyData{
		Username:  username,
		PublicKey: string(pubPem),
	}
	authDataBytes, err := json.Marshal(authData)
	if err != nil {
		return fmt.Errorf("error marshaling auth key data: %v", err)
	}

	encryptedData, err := pcrypto.EncryptServer(authDataBytes)
	if err != nil {
		return fmt.Errorf("error encrypting auth key data: %v", err)
	}

	if err := db.Put("auth_public_keys", store.HashBytes([]byte(userUUID)), encryptedData); err != nil {
		return fmt.Errorf("error storing auth public key in DB: %v", err)
	}
	return nil
}

func InitiatePublicKeyLogin(db store.Store, email string) (string, string, string, error) {
	encryptedUUID, err := db.Get(bucketAuthUUID, store.HashBytes([]byte(email)))
	if err != nil {
		return "", "", "", errors.New("user not found for public key login")
	}
	userUUID, err := pcrypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return "", "", "", fmt.Errorf("error decrypting user UUID: %v", err)
	}
	encryptedData, err := db.Get("auth_public_keys", store.HashBytes([]byte(userUUID)))
	if err != nil {
		return "", "", "", errors.New("auth public key not found")
	}
	decryptedData, err := pcrypto.DecryptServer(encryptedData)
	if err != nil {
		return "", "", "", fmt.Errorf("error decrypting auth key data: %v", err)
	}
	var authData AuthKeyData
	if err := json.Unmarshal(decryptedData, &authData); err != nil {
		return "", "", "", fmt.Errorf("error unmarshaling auth key data: %v", err)
	}

	keyUUID := store.HashBytes([]byte(userUUID))
	role, err := db.Get("cheese_roles", keyUUID)
	if err != nil {
		return "", "", "", fmt.Errorf("error retrieving user role: %v", err)
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", "", fmt.Errorf("error generating nonce: %v", err)
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	nonceMu.Lock()
	nonceMap[email] = nonceInfo{
		Nonce:     nonce,
		Timestamp: time.Now(),
	}
	nonceMu.Unlock()
	return nonce, authData.Username, string(role), nil
}

func VerifyPublicKeyLogin(db store.Store, email string, signatureB64 string) (string, string, string, string, error) {
	// Lock and fetch the stored nonce for this email
	nonceMu.Lock()
	nInfo, exists := nonceMap[email]
	if !exists {
		nonceMu.Unlock()
		return "", "", "", "", errors.New("no challenge found for this email")
	}
	if time.Since(nInfo.Timestamp) > 5*time.Minute {
		delete(nonceMap, email)
		nonceMu.Unlock()
		return "", "", "", "", errors.New("challenge expired")
	}
	delete(nonceMap, email)
	nonceMu.Unlock()

	encryptedUUID, err := db.Get(bucketAuthUUID, store.HashBytes([]byte(email)))
	if err != nil {
		return "", "", "", "", errors.New("user not found for public key login")
	}
	userUUID, err := pcrypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return "", "", "", "", fmt.Errorf("error decrypting user UUID: %v", err)
	}

	keyUUID := store.HashBytes([]byte(userUUID))
	if _, err := db.Get("cheese_banned_users", keyUUID); err == nil {
		return "", "", "", "", errors.New("user is banned")
	}

	encryptedAuthData, err := db.Get("auth_public_keys", keyUUID)
	if err != nil {
		return "", "", "", "", errors.New("auth public key not found")
	}
	authDataBytes, err := pcrypto.DecryptServer(encryptedAuthData)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error decrypting auth key data: %v", err)
	}
	var authData AuthKeyData
	if err := json.Unmarshal(authDataBytes, &authData); err != nil {
		return "", "", "", "", fmt.Errorf("error unmarshaling auth key data: %v", err)
	}
	block, _ := pem.Decode([]byte(authData.PublicKey))
	if block == nil {
		return "", "", "", "", errors.New("failed to parse public key PEM")
	}
	pubIface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error parsing public key: %v", err)
	}
	pubKey, ok := pubIface.(*rsa.PublicKey)
	if !ok {
		return "", "", "", "", errors.New("public key is not RSA")
	}

	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error decoding signature: %v", err)
	}
	hash := sha3.Sum256([]byte(nInfo.Nonce))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA3_256, hash[:], sig); err != nil {
		return "", "", "", "", errors.New("signature verification failed")
	}

	roleBytes, err := db.Get("cheese_roles", keyUUID)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error retrieving user role: %v", err)
	}
	groupBytes, err := db.Get("cheese_user_group", keyUUID)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error retrieving user group: %v", err)
	}

	accessToken, err := token.GenerateAccessToken(userUUID)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error generating access token: %v", err)
	}
	refreshToken, err := token.GenerateRefreshToken(userUUID)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error generating refresh token: %v", err)
	}

	hashedRefresh := store.HashBytes([]byte(refreshToken))
	if err := db.Put("cheese_refresh", keyUUID, hashedRefresh); err != nil {
		return "", "", "", "", fmt.Errorf("error saving refresh token: %v", err)
	}

	return accessToken, refreshToken, string(roleBytes), string(groupBytes), nil
}

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
