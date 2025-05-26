package functionalities

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	"golang.org/x/crypto/sha3"

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

	seccrypto "prac/pkg/crypto"
)

const (
	RSAKeySize     = 2048
	KeysFolder     = "keys/users"
	PrivateKeyFile = "private.pem"
	PublicKeyFile  = "public.pem"
)

type EncryptedPacket struct {
	EncryptedSymKey       string `json:"encryptedSymKey"`
	EncryptedSymKeySender string `json:"encryptedSymKeySender"`
	EncryptedMsg          string `json:"encryptedMsg"`
	Signature             string `json:"signature"`
	Timestamp             int64  `json:"timestamp"`
}

func GenerateKeyPair(username string) error {
	userFolder := filepath.Join(KeysFolder, username)
	if err := os.MkdirAll(userFolder, 0700); err != nil {
		return fmt.Errorf("error creating user key folder: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return fmt.Errorf("error generating RSA key pair: %v", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	privPath := filepath.Join(userFolder, PrivateKeyFile)
	if err := ioutil.WriteFile(privPath, privPem, 0600); err != nil {
		return fmt.Errorf("error saving private key: %v", err)
	}

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

func SignMessage(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha3.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA3_256, hashed[:])

	if err != nil {
		return nil, fmt.Errorf("error signing message: %v", err)
	}
	return signature, nil
}

func VerifySignature(message, signature []byte, publicKey *rsa.PublicKey) error {
	hashed := sha3.Sum256(message)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA3_256, hashed[:], signature)

	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}
	return nil
}

func EncryptWithPublicKey(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	label := []byte("") // empty label
	encryptedData, err := rsa.EncryptOAEP(sha3.New256(), rand.Reader, publicKey, data, label)
	if err != nil {
		return nil, fmt.Errorf("error encrypting with public key: %v", err)
	}
	return encryptedData, nil
}

func DecryptWithPrivateKey(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	decryptedData, err := rsa.DecryptOAEP(sha3.New256(), rand.Reader, privateKey, data, label)
	if err != nil {
		return nil, fmt.Errorf("error decrypting with private key: %v", err)
	}
	return decryptedData, nil
}

func generateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, fmt.Errorf("error generating random bytes: %v", err)
	}
	return bytes, nil
}

func CreateEncryptedPacket(message []byte, recipientPub *rsa.PublicKey, senderPriv *rsa.PrivateKey) (*EncryptedPacket, error) {
	symKey, err := generateRandomBytes(32)
	if err != nil {
		return nil, err
	}

	encryptedMsg, err := seccrypto.Encrypt(message, symKey)
	if err != nil {
		return nil, fmt.Errorf("error encrypting message symmetrically: %v", err)
	}

	encryptedSymKeyRecipient, err := EncryptWithPublicKey(symKey, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("error encrypting symmetric key for recipient: %v", err)
	}

	senderPub := &senderPriv.PublicKey
	encryptedSymKeySender, err := EncryptWithPublicKey(symKey, senderPub)
	if err != nil {
		return nil, fmt.Errorf("error encrypting symmetric key for sender: %v", err)
	}

	timestamp := time.Now().Unix()

	signData := append([]byte(fmt.Sprintf("%d", timestamp)), encryptedMsg...)

	signature, err := SignMessage(signData, senderPriv)
	if err != nil {
		return nil, err
	}

	packet := &EncryptedPacket{
		EncryptedSymKey:       base64.StdEncoding.EncodeToString(encryptedSymKeyRecipient),
		EncryptedSymKeySender: base64.StdEncoding.EncodeToString(encryptedSymKeySender),
		EncryptedMsg:          base64.StdEncoding.EncodeToString(encryptedMsg),
		Signature:             base64.StdEncoding.EncodeToString(signature),
		Timestamp:             timestamp,
	}
	return packet, nil
}

func DecryptEncryptedPacket(packet *EncryptedPacket, recipientPriv *rsa.PrivateKey, senderPub *rsa.PublicKey, isSender bool) ([]byte, error) {
	var encSymKeyB64 string
	if isSender {
		encSymKeyB64 = packet.EncryptedSymKeySender
	} else {
		encSymKeyB64 = packet.EncryptedSymKey
	}

	encSymKey, err := base64.StdEncoding.DecodeString(encSymKeyB64)
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

	symKey, err := DecryptWithPrivateKey(encSymKey, recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("error decrypting symmetric key: %v", err)
	}

	message, err := seccrypto.Decrypt(encMsg, symKey)
	if err != nil {
		return nil, fmt.Errorf("error decrypting message: %v", err)
	}

	signData := append([]byte(fmt.Sprintf("%d", packet.Timestamp)), encMsg...)

	// Verify the signature.
	if err := VerifySignature(signData, signature, senderPub); err != nil {
		return nil, err
	}

	return message, nil
}
