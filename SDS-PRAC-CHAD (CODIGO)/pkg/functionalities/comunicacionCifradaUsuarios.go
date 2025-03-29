// File: functionalities/comunicacionCifradaUsuarios.go
package functionalities

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	seccrypto "prac/pkg/crypto" // alias for your local crypto package
)

// Constants for RSA key size and file storage paths.
const (
	RSAKeySize     = 2048
	KeysFolder     = "keys/users"
	PrivateKeyFile = "private.pem"
	PublicKeyFile  = "public.pem"
)

// EncryptedPacket defines the structure that holds the encrypted symmetric key,
// the encrypted message, the digital signature and a timestamp.
type EncryptedPacket struct {
	EncryptedSymKey string // base64 encoded encrypted symmetric key
	EncryptedMsg    string // base64 encoded AES-GCM ciphertext (nonce prepended)
	Signature       string // base64 encoded digital signature
	Timestamp       int64  // Unix timestamp
}

// GenerateKeyPair generates a new RSA key pair for the given user and saves them to disk.
func GenerateKeyPair(username string) error {
	// Create the folder for user keys if it does not exist.
	userFolder := filepath.Join(KeysFolder, username)
	if err := os.MkdirAll(userFolder, 0700); err != nil {
		return fmt.Errorf("error creating user key folder: %v", err)
	}

	// Generate RSA private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return fmt.Errorf("error generating RSA key pair: %v", err)
	}

	// Encode and save private key.
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	privPath := filepath.Join(userFolder, PrivateKeyFile)
	if err := ioutil.WriteFile(privPath, privPem, 0600); err != nil {
		return fmt.Errorf("error saving private key: %v", err)
	}

	// Encode and save public key.
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error marshalling public key: %v", err)
	}
	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	})
	pubPath := filepath.Join(userFolder, PublicKeyFile)
	if err := ioutil.WriteFile(pubPath, pubPem, 0644); err != nil {
		return fmt.Errorf("error saving public key: %v", err)
	}

	return nil
}

// LoadPrivateKey loads the RSA private key for the given user from disk.
func LoadPrivateKey(username string) (*rsa.PrivateKey, error) {
	privPath := filepath.Join(KeysFolder, username, PrivateKeyFile)
	privPem, err := ioutil.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("error reading private key: %v", err)
	}
	block, _ := pem.Decode(privPem)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid private key PEM")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}
	return privateKey, nil
}

// LoadPublicKey loads the RSA public key for the given user from disk.
func LoadPublicKey(username string) (*rsa.PublicKey, error) {
	pubPath := filepath.Join(KeysFolder, username, PublicKeyFile)
	pubPem, err := ioutil.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("error reading public key: %v", err)
	}
	block, _ := pem.Decode(pubPem)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("invalid public key PEM")
	}
	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}
	pubKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return pubKey, nil
}

// SignMessage signs the given message using the provided RSA private key.
// It returns the digital signature.
func SignMessage(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("error signing message: %v", err)
	}
	return signature, nil
}

// VerifySignature verifies the digital signature for the message using the sender's public key.
func VerifySignature(message, signature []byte, publicKey *rsa.PublicKey) error {
	hashed := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}
	return nil
}

// EncryptWithPublicKey encrypts data using RSA OAEP with the recipient's public key.
func EncryptWithPublicKey(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	label := []byte("") // empty label
	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, label)
	if err != nil {
		return nil, fmt.Errorf("error encrypting with public key: %v", err)
	}
	return encryptedData, nil
}

// DecryptWithPrivateKey decrypts data using RSA OAEP with the recipient's private key.
func DecryptWithPrivateKey(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, data, label)
	if err != nil {
		return nil, fmt.Errorf("error decrypting with private key: %v", err)
	}
	return decryptedData, nil
}

// generateRandomBytes returns securely generated random bytes of given length.
func generateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, fmt.Errorf("error generating random bytes: %v", err)
	}
	return bytes, nil
}

// CreateEncryptedPacket performs the following:
// 1. Generates a random symmetric key.
// 2. Encrypts the message using AES-GCM (via the existing seccrypto.Encrypt).
// 3. Encrypts the symmetric key with the recipient's public key.
// 4. Signs the original message using the sender's private key.
// 5. Returns an EncryptedPacket.
func CreateEncryptedPacket(message []byte, recipientPub *rsa.PublicKey, senderPriv *rsa.PrivateKey) (*EncryptedPacket, error) {
	// Generate a random symmetric key (32 bytes for AES-256)
	symKey, err := generateRandomBytes(32)
	if err != nil {
		return nil, err
	}

	// Encrypt the message with the symmetric key using AES-GCM.
	encryptedMsg, err := seccrypto.Encrypt(message, symKey)
	if err != nil {
		return nil, fmt.Errorf("error encrypting message symmetrically: %v", err)
	}

	// Encrypt the symmetric key with recipient's public key.
	encryptedSymKey, err := EncryptWithPublicKey(symKey, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("error encrypting symmetric key: %v", err)
	}

	// Create a timestamp.
	timestamp := time.Now().Unix()

	// Prepare a data blob for signing (e.g., the concatenation of the timestamp and the encrypted message).
	signData := append([]byte(fmt.Sprintf("%d", timestamp)), encryptedMsg...)

	// Sign the data.
	signature, err := SignMessage(signData, senderPriv)
	if err != nil {
		return nil, err
	}

	packet := &EncryptedPacket{
		EncryptedSymKey: base64.StdEncoding.EncodeToString(encryptedSymKey),
		EncryptedMsg:    base64.StdEncoding.EncodeToString(encryptedMsg),
		Signature:       base64.StdEncoding.EncodeToString(signature),
		Timestamp:       timestamp,
	}
	return packet, nil
}

// DecryptEncryptedPacket decrypts an EncryptedPacket.
// It decrypts the symmetric key using the recipient's private key, then decrypts the message.
// It also verifies the digital signature using the sender's public key.
func DecryptEncryptedPacket(packet *EncryptedPacket, recipientPriv *rsa.PrivateKey, senderPub *rsa.PublicKey) ([]byte, error) {
	// Decode the base64 encoded fields.
	encSymKey, err := base64.StdEncoding.DecodeString(packet.EncryptedSymKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding encrypted symmetric key: %v", err)
	}
	encMsg, err := base64.StdEncoding.DecodeString(packet.EncryptedMsg)
	if err != nil {
		return nil, fmt.Errorf("error decoding encrypted message: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString(packet.Signature)
	if err != nil {
		return nil, fmt.Errorf("error decoding signature: %v", err)
	}

	// Decrypt the symmetric key using recipient's private key.
	symKey, err := DecryptWithPrivateKey(encSymKey, recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("error decrypting symmetric key: %v", err)
	}

	// Decrypt the message using the symmetric key.
	message, err := seccrypto.Decrypt(encMsg, symKey)
	if err != nil {
		return nil, fmt.Errorf("error decrypting message: %v", err)
	}

	// Recreate the signData used in signing.
	signData := append([]byte(fmt.Sprintf("%d", packet.Timestamp)), encMsg...)

	// Verify the signature.
	if err := VerifySignature(signData, signature, senderPub); err != nil {
		return nil, err
	}

	return message, nil
}
