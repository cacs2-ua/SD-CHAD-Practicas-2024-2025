package server

import (
	"crypto/ed25519"
	"crypto/x509"
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
	"golang.org/x/crypto/bcrypt"
)

var (
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
)

// AuthRecord represents the data stored in the "auth" bucket.
type AuthRecord struct {
	Password      string `json:"password"`
	EncryptedUUID string `json:"encrypted_uuid"`
}

// init loads the Ed25519 private and public keys from the "keys" folder.
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
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
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
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// serverImpl encapsulates the state of our server.
type serverImpl struct {
	db  store.Store // database
	log *log.Logger // logger for error and info messages
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

// userNameToUUID retrieves the decrypted UUID from the "auth" bucket for a given username.
func (s *serverImpl) userNameToUUID(username string) (string, error) {
	// Key is HashBytes(username) in "auth" bucket.
	key := store.HashBytes([]byte(username))
	data, err := s.db.Get("auth", key)
	if err != nil {
		return "", err
	}
	var record AuthRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return "", err
	}
	// Decrypt the stored encrypted UUID.
	uuidStr, err := crypto.DecryptUUID(record.EncryptedUUID)
	if err != nil {
		return "", err
	}
	return uuidStr, nil
}

// registerUser registers a new user.
// It generates a unique UUID, encrypts it, and stores an auth record in the "auth" bucket
// with key = HashBytes(username) and value = JSON {password, encrypted_uuid}.
// It stores an empty entry in "userdata" with key = HashBytes(UUID).
func (s *serverImpl) registerUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if len(req.Password) < 8 {
		return api.Response{Success: false, Message: "Password must have at least 8 characters"}
	}
	// Check if user already exists.
	if _, err := s.userNameToUUID(req.Username); err == nil {
		return api.Response{Success: false, Message: "User already exists"}
	}
	// Generate new UUID.
	userUUID := uuid.New().String()
	// Encrypt the UUID.
	encryptedUUID, err := crypto.EncryptUUID(userUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error encrypting UUID"}
	}
	// Hash the password.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return api.Response{Success: false, Message: "Error hashing password"}
	}
	// Create auth record.
	record := AuthRecord{
		Password:      string(hashedPassword),
		EncryptedUUID: encryptedUUID,
	}
	recordData, err := json.Marshal(record)
	if err != nil {
		return api.Response{Success: false, Message: "Error marshalling auth record"}
	}
	// Store in "auth" bucket with key = HashBytes(username).
	if err := s.db.Put("auth", store.HashBytes([]byte(req.Username)), recordData); err != nil {
		return api.Response{Success: false, Message: "Error saving credentials"}
	}
	// In "userdata" bucket, store an empty string with key = HashBytes([]byte(userUUID)).
	if err := s.db.Put("userdata", store.HashBytes([]byte(userUUID)), []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error initializing user data"}
	}
	return api.Response{Success: true, Message: "User registered"}
}

// loginUser validates credentials and generates tokens.
// It retrieves the auth record using HashBytes(username), verifies the password,
// decrypts the UUID, then generates tokens with subject = userUUID.
func (s *serverImpl) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if len(req.Password) < 8 {
		return api.Response{Success: false, Message: "Password must have at least 8 characters"}
	}
	key := store.HashBytes([]byte(req.Username))
	data, err := s.db.Get("auth", key)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}
	var record AuthRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return api.Response{Success: false, Message: "Error reading auth record"}
	}
	if err := bcrypt.CompareHashAndPassword([]byte(record.Password), []byte(req.Password)); err != nil {
		return api.Response{Success: false, Message: "Invalid credentials"}
	}
	userUUID, err := crypto.DecryptUUID(record.EncryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error decrypting UUID"}
	}
	accessToken, err := generateAccessToken(userUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating access token"}
	}
	refreshToken, err := generateRefreshToken(userUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating refresh token"}
	}
	// Store refresh token in "refresh" bucket with key = HashBytes([]byte(userUUID)).
	if err := s.db.Put("refresh", store.HashBytes([]byte(userUUID)), []byte(refreshToken)); err != nil {
		return api.Response{Success: false, Message: "Error saving refresh token"}
	}
	return api.Response{
		Success:      true,
		Message:      "Login successful",
		Token:        accessToken,
		RefreshToken: refreshToken,
	}
}

// refreshToken validates the refresh token and generates new tokens.
func (s *serverImpl) refreshToken(req api.Request) api.Response {
	if req.Username == "" || req.RefreshToken == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	userUUID, err := s.userNameToUUID(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}
	storedToken, err := s.db.Get("refresh", store.HashBytes([]byte(userUUID)))
	if err != nil {
		return api.Response{Success: false, Message: "Refresh token not found"}
	}
	if string(storedToken) != req.RefreshToken {
		return api.Response{Success: false, Message: "Invalid refresh token"}
	}
	token, err := jwt.Parse(req.RefreshToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		return api.Response{Success: false, Message: "Expired or invalid refresh token"}
	}
	newAccessToken, err := generateAccessToken(userUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating new access token"}
	}
	newRefreshToken, err := generateRefreshToken(userUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating new refresh token"}
	}
	if err := s.db.Put("refresh", store.HashBytes([]byte(userUUID)), []byte(newRefreshToken)); err != nil {
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
	userUUID, err := s.userNameToUUID(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}
	if !s.isAccessTokenValid(userUUID, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired access token"}
	}
	rawData, err := s.db.Get("userdata", store.HashBytes([]byte(userUUID)))
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
	userUUID, err := s.userNameToUUID(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}
	if !s.isAccessTokenValid(userUUID, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired access token"}
	}
	if err := s.db.Put("userdata", store.HashBytes([]byte(userUUID)), []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error updating user data"}
	}
	return api.Response{Success: true, Message: "User data updated"}
}

// logoutUser deletes the refresh token, invalidating the session.
func (s *serverImpl) logoutUser(req api.Request) api.Response {
	if req.Username == "" || req.RefreshToken == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	userUUID, err := s.userNameToUUID(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}
	if err := s.db.Delete("refresh", store.HashBytes([]byte(userUUID))); err != nil {
		return api.Response{Success: false, Message: "Error closing session"}
	}
	return api.Response{Success: true, Message: "Session closed successfully"}
}

// userExists checks if a user exists by looking up the username in the "auth" bucket.
func (s *serverImpl) userExists(username string) (bool, error) {
	_, err := s.userNameToUUID(username)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isAccessTokenValid verifies the access token's signature and expiration using the user UUID.
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
