package server

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"prac/pkg/api"
	"prac/pkg/crypto"
	"prac/pkg/store"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
)

// bucketAuthUUID and bucketAuthPassword are the hashed names of the new buckets.
// We use store.HashBytes([]byte("auth_uuid")) so that the actual bucket name is not stored in clear text.
var bucketAuthUUID = store.HashBytes([]byte("auth_uuid"))
var bucketAuthPassword = store.HashBytes([]byte("auth_password"))

// init loads the Ed25519 private and public keys from the "keys" folder.
var (
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
)

func init() {
	// Load private key from keys/private.pem
	privBytes, err := ioutil.ReadFile("keys/private.pem")
	if err != nil {
		log.Fatalf("Error reading private key: %v", err)
	}
	block, _ := pem.Decode(privBytes)
	if block == nil {
		log.Fatal("Failed to parse PEM block containing the private key")
	}
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
	}
	var ok bool
	privateKey, ok = keyInterface.(ed25519.PrivateKey)
	if !ok {
		log.Fatal("Private key is not of type Ed25519")
	}

	// Load public key from keys/public.pem
	pubBytes, err := ioutil.ReadFile("keys/public.pem")
	if err != nil {
		log.Fatalf("Error reading public key: %v", err)
	}
	block, _ = pem.Decode(pubBytes)
	if block == nil {
		log.Fatal("Failed to parse PEM block containing the public key")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing public key: %v", err)
	}
	publicKey, ok = pubInterface.(ed25519.PublicKey)
	if !ok {
		log.Fatal("Public key is not of type Ed25519")
	}
}

// generateAccessToken creates an access JWT for the given user UUID with short expiration.
func generateAccessToken(userUUID string) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   userUUID,
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
		Issuer:    "prac-server",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(privateKey)
}

// generateRefreshToken creates a refresh JWT for the given user UUID with longer expiration.
func generateRefreshToken(userUUID string) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   userUUID,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Issuer:    "prac-server",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(privateKey)
}

// hashPasswordSHA3 hashes a password using SHA-3 (SHA-256) and returns a hex-encoded string.
func hashPasswordSHA3(password string) string {
	hasher := sha3.New256()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

// serverImpl encapsulates the state of our server.
type serverImpl struct {
	db  store.Store
	log *log.Logger
}

// Run starts the database and the HTTPS server.
func Run() error {
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error opening database: %v", err)
	}
	srv := &serverImpl{
		db:  db,
		log: log.New(os.Stdout, "[srv] ", log.LstdFlags),
	}
	defer srv.db.Close()

	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))
	err = http.ListenAndServeTLS(":8080", "certs/server.crt", "certs/server.key", mux)
	return err
}

// apiHandler decodes the JSON request, dispatches it, and returns the JSON response.
func (s *serverImpl) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req api.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}
	var res api.Response
	switch req.Action {
	case api.ActionRegister:
		res = s.registerUser(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionRefresh:
		res = s.refreshToken(req)
	case api.ActionFetchData:
		res = s.fetchData(req)
	case api.ActionUpdateData:
		res = s.updateData(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	default:
		res = api.Response{Success: false, Message: "Unknown action"}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// registerUser creates two entries: one in auth_uuid for the encrypted UUID, and one in auth_password for the hashed password.
func (s *serverImpl) registerUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if len(req.Password) < 8 {
		return api.Response{Success: false, Message: "Password must have at least 8 characters"}
	}

	// Check if user already exists by looking up in auth_password bucket.
	if exists, _ := s.userExists(req.Username); exists {
		return api.Response{Success: false, Message: "User already exists"}
	}

	// Generate a new UUID for the user.
	userUUID := uuid.New().String()

	// Encrypt the UUID with the existing logic.
	encryptedUUID, err := crypto.EncryptUUID(userUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error encrypting UUID"}
	}

	// Hash the password with SHA-3 (SHA-256).
	hashedPassword := hashPasswordSHA3(req.Password)

	// Store the encrypted UUID in "auth_uuid" bucket, with key = hashed username.
	keyUsername := store.HashBytes([]byte(req.Username))
	if err := s.db.Put(string(bucketAuthUUID), keyUsername, []byte(encryptedUUID)); err != nil {
		return api.Response{Success: false, Message: "Error saving encrypted UUID"}
	}

	// Store the hashed password in "auth_password" bucket, with key = hashed username.
	if err := s.db.Put(string(bucketAuthPassword), keyUsername, []byte(hashedPassword)); err != nil {
		return api.Response{Success: false, Message: "Error saving hashed password"}
	}

	// Create an empty entry for user data in "userdata" bucket, key = hashed userUUID.
	hashedUUID := store.HashBytes([]byte(userUUID))
	if err := s.db.Put("userdata", hashedUUID, []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error initializing user data"}
	}

	return api.Response{Success: true, Message: "User registered"}
}

// loginUser verifies the hashed password in auth_password, retrieves the encrypted UUID in auth_uuid, decrypts it, then generates tokens.
func (s *serverImpl) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if len(req.Password) < 8 {
		return api.Response{Success: false, Message: "Password must have at least 8 characters"}
	}

	// Check if user exists in auth_password.
	keyUsername := store.HashBytes([]byte(req.Username))
	hashedPassVal, err := s.db.Get(string(bucketAuthPassword), keyUsername)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}
	// Compare the hashed password.
	incomingHashed := hashPasswordSHA3(req.Password)
	if string(hashedPassVal) != incomingHashed {
		return api.Response{Success: false, Message: "Invalid credentials"}
	}

	// Retrieve the encrypted UUID from auth_uuid.
	encryptedUUID, err := s.db.Get(string(bucketAuthUUID), keyUsername)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving UUID"}
	}
	decryptedUUID, err := crypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return api.Response{Success: false, Message: "Error decrypting UUID"}
	}

	// Generate access and refresh tokens.
	accessToken, err := generateAccessToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating access token"}
	}
	refreshToken, err := generateRefreshToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating refresh token"}
	}

	// Store the refresh token in "refresh" bucket with key = hashed userUUID.
	hashedUUID := store.HashBytes([]byte(decryptedUUID))
	if err := s.db.Put("refresh", hashedUUID, []byte(refreshToken)); err != nil {
		return api.Response{Success: false, Message: "Error saving refresh token"}
	}

	return api.Response{
		Success:      true,
		Message:      "Login successful",
		Token:        accessToken,
		RefreshToken: refreshToken,
	}
}

// refreshToken uses the user's hashed password bucket to find the encrypted UUID, etc.
func (s *serverImpl) refreshToken(req api.Request) api.Response {
	if req.Username == "" || req.RefreshToken == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}

	// Retrieve the encrypted UUID from auth_uuid.
	keyUsername := store.HashBytes([]byte(req.Username))
	encryptedUUID, err := s.db.Get(string(bucketAuthUUID), keyUsername)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}
	decryptedUUID, err := crypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return api.Response{Success: false, Message: "Error decrypting UUID"}
	}

	// Retrieve the existing refresh token from "refresh" bucket using hashed userUUID.
	hashedUUID := store.HashBytes([]byte(decryptedUUID))
	storedToken, err := s.db.Get("refresh", hashedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Refresh token not found"}
	}
	if string(storedToken) != req.RefreshToken {
		return api.Response{Success: false, Message: "Invalid refresh token"}
	}

	// Verify expiration.
	token, err := jwt.Parse(req.RefreshToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		return api.Response{Success: false, Message: "Expired or invalid refresh token"}
	}

	// Generate new tokens.
	newAccessToken, err := generateAccessToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating new access token"}
	}
	newRefreshToken, err := generateRefreshToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating new refresh token"}
	}

	// Update the refresh token in "refresh" bucket.
	if err := s.db.Put("refresh", hashedUUID, []byte(newRefreshToken)); err != nil {
		return api.Response{Success: false, Message: "Error updating refresh token"}
	}

	return api.Response{
		Success:      true,
		Message:      "Tokens refreshed successfully",
		Token:        newAccessToken,
		RefreshToken: newRefreshToken,
	}
}

// fetchData verifies the access token and returns the content from the "userdata" bucket.
func (s *serverImpl) fetchData(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	decryptedUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	if !s.isAccessTokenValid(decryptedUUID, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired access token"}
	}
	hashedUUID := store.HashBytes([]byte(decryptedUUID))
	rawData, err := s.db.Get("userdata", hashedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving user data"}
	}
	return api.Response{
		Success: true,
		Message: "Private data for " + req.Username,
		Data:    string(rawData),
	}
}

// updateData updates the content of "userdata" after verifying the access token.
func (s *serverImpl) updateData(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	decryptedUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	if !s.isAccessTokenValid(decryptedUUID, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired access token"}
	}
	hashedUUID := store.HashBytes([]byte(decryptedUUID))
	if err := s.db.Put("userdata", hashedUUID, []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error updating user data"}
	}
	return api.Response{Success: true, Message: "User data updated"}
}

// logoutUser deletes the refresh token, invalidating the session.
func (s *serverImpl) logoutUser(req api.Request) api.Response {
	if req.Username == "" || req.RefreshToken == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	decryptedUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	hashedUUID := store.HashBytes([]byte(decryptedUUID))
	if err := s.db.Delete("refresh", hashedUUID); err != nil {
		return api.Response{Success: false, Message: "Error closing session"}
	}
	return api.Response{Success: true, Message: "Session closed successfully"}
}

// userExists checks if the user has an entry in auth_password (meaning they are registered).
func (s *serverImpl) userExists(username string) (bool, error) {
	keyUsername := store.HashBytes([]byte(username))
	_, err := s.db.Get(string(bucketAuthPassword), keyUsername)
	if err != nil {
		if strings.Contains(err.Error(), "key not found") {
			return false, nil
		}
		if strings.Contains(err.Error(), "bucket not found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isAccessTokenValid verifies the token signature and expiration.
func (s *serverImpl) isAccessTokenValid(userUUID, tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	if claims["sub"] != userUUID {
		return false
	}
	return true
}

// lookupUUIDFromUsername retrieves the user's encrypted UUID from auth_uuid and decrypts it.
func (s *serverImpl) lookupUUIDFromUsername(username string) (string, error) {
	keyUsername := store.HashBytes([]byte(username))
	encryptedUUID, err := s.db.Get(string(bucketAuthUUID), keyUsername)
	if err != nil {
		return "", fmt.Errorf("User not found")
	}
	decryptedUUID, err := crypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return "", fmt.Errorf("Error decrypting UUID")
	}
	return decryptedUUID, nil
}
