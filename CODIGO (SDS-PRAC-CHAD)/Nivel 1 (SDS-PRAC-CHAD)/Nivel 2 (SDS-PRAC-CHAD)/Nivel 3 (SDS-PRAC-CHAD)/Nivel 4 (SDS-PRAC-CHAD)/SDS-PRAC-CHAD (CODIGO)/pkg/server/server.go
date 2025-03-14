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
	"regexp"
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
var bucketAuthUUID = store.HashBytes([]byte("auth_uuid"))
var bucketAuthPassword = store.HashBytes([]byte("auth_password"))
var bucketAuthEmail = store.HashBytes([]byte("auth_email"))

// AuthRecord represents the data stored in the auth buckets.
type AuthRecord struct {
	EncryptedUUID string `json:"encrypted_uuid"`
}

var (
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
)

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

// validateJWTSignature parses the token string and validates its signature using the public key.
// It returns the parsed token if valid, or an error otherwise.
func validateJWTSignature(tokenStr string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		// Check that the token is signed with the expected method.
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}
	return token, nil
}

// generateAccessToken creates an access JWT for the given user UUID with short expiration.
func generateAccessToken(userUUID string) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   userUUID,
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
		Issuer:    "tomato-potato-server",
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
		Issuer:    "tomato-potato-server",
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

// hashRefreshToken returns the SHA3-256 hash (hex-encoded) of the refresh token.
func hashRefreshToken(token string) string {
	hasher := sha3.New256()
	hasher.Write([]byte(token))
	return hex.EncodeToString(hasher.Sum(nil))
}

// isValidEmail validates the email format using a regex.
func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
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

// apiHandler decodes the JSON request, extracts the JWT tokens from the proper headers,
// dispatches the request and returns the JSON response.
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

	// Extract access token from "Authorization" header.
	authHeader := r.Header.Get("Authorization")
	var providedAccessToken string
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			providedAccessToken = parts[1]
		}
	}

	// Extract refresh token from "X-Refresh-Token" header.
	refreshHeader := r.Header.Get("X-Refresh-Token")
	var providedRefreshToken string
	if refreshHeader != "" {
		parts := strings.SplitN(refreshHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			providedRefreshToken = parts[1]
		}
	}

	var res api.Response
	var newAccessToken, newRefreshToken string

	switch req.Action {
	case api.ActionRegister:
		res = s.registerUser(req)
	case api.ActionLogin:
		res, newAccessToken, newRefreshToken = s.loginUser(req)
	case api.ActionRefresh:
		res, newAccessToken, newRefreshToken = s.refreshToken(req, providedRefreshToken)
	case api.ActionFetchData:
		res = s.fetchData(req, providedAccessToken)
	case api.ActionUpdateData:
		res = s.updateData(req, providedAccessToken)
	case api.ActionLogout:
		res = s.logoutUser(req, providedRefreshToken)
	default:
		res = api.Response{Success: false, Message: "Unknown action"}
	}

	// Set tokens in headers for actions that generate tokens.
	if newAccessToken != "" {
		w.Header().Set("Authorization", "Bearer "+newAccessToken)
	}
	if newRefreshToken != "" {
		w.Header().Set("X-Refresh-Token", "Bearer "+newRefreshToken)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// registerUser creates three entries: one in auth_uuid for the encrypted UUID,
// one in auth_password for the hashed password, and one in auth_email for the encrypted username.
func (s *serverImpl) registerUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" || req.Email == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if len(req.Username) < 8 {
		return api.Response{Success: false, Message: "Username must have at least 8 characters"}
	}
	if len(req.Password) < 8 {
		return api.Response{Success: false, Message: "Password must have at least 8 characters"}
	}
	if !isValidEmail(req.Email) {
		return api.Response{Success: false, Message: "Invalid email format"}
	}
	// Check if user already exists by username.
	if exists, _ := s.userExists(req.Username); exists {
		return api.Response{Success: false, Message: "User already exists"}
	}
	// Check if email already exists.
	_, err := s.db.Get(string(bucketAuthEmail), store.HashBytes([]byte(req.Email)))
	if err == nil {
		return api.Response{Success: false, Message: "Email already in use"}
	}
	// Generate a new UUID.
	userUUID := uuid.New().String()
	// Encrypt the UUID.
	encryptedUUID, err := crypto.EncryptUUID(userUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error encrypting UUID"}
	}
	// Hash the password using SHA3.
	hashedPassword := hashPasswordSHA3(req.Password)
	// Store encrypted UUID in auth_uuid bucket, key = HashBytes(username).
	keyUsername := store.HashBytes([]byte(req.Username))
	if err := s.db.Put(string(bucketAuthUUID), keyUsername, []byte(encryptedUUID)); err != nil {
		return api.Response{Success: false, Message: "Error saving encrypted UUID"}
	}
	// Store hashed password in auth_password bucket, key = HashBytes(username).
	if err := s.db.Put(string(bucketAuthPassword), keyUsername, []byte(hashedPassword)); err != nil {
		return api.Response{Success: false, Message: "Error saving hashed password"}
	}
	// Encrypt username using AES-GCM-256 with key from keys/username.key.
	encryptedUsername, err := crypto.EncryptUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error encrypting username"}
	}
	// Store in auth_email bucket, key = HashBytes(email).
	keyEmail := store.HashBytes([]byte(req.Email))
	if err := s.db.Put(string(bucketAuthEmail), keyEmail, []byte(encryptedUsername)); err != nil {
		return api.Response{Success: false, Message: "Error saving encrypted username"}
	}
	// In userdata bucket, store an empty string with key = HashBytes(userUUID).
	hashedUUID := store.HashBytes([]byte(userUUID))
	if err := s.db.Put("userdata", hashedUUID, []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error initializing user data"}
	}
	return api.Response{Success: true, Message: "User registered"}
}

// lookupUsernameFromEmail retrieves the encrypted username from auth_email and decrypts it.
func (s *serverImpl) lookupUsernameFromEmail(email string) (string, error) {
	keyEmail := store.HashBytes([]byte(email))
	encryptedUsername, err := s.db.Get(string(bucketAuthEmail), keyEmail)
	if err != nil {
		return "", fmt.Errorf("Email not found")
	}
	decryptedUsername, err := crypto.DecryptUsername(string(encryptedUsername))
	if err != nil {
		return "", fmt.Errorf("Error decrypting username")
	}
	return decryptedUsername, nil
}

// loginUser verifies the hashed password in auth_password, retrieves the encrypted UUID from auth_uuid,
// decrypts it, then generates tokens. The refresh token is stored hashed.
// It now uses email and password. The decrypted username is returned in Data.
func (s *serverImpl) loginUser(req api.Request) (api.Response, string, string) {
	if req.Email == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Missing credentials"}, "", ""
	}
	if !isValidEmail(req.Email) {
		return api.Response{Success: false, Message: "Invalid email format"}, "", ""
	}
	if len(req.Password) < 8 {
		return api.Response{Success: false, Message: "Password must have at least 8 characters"}, "", ""
	}
	// Lookup username from email.
	username, err := s.lookupUsernameFromEmail(req.Email)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}, "", ""
	}
	// Retrieve hashed password from auth_password using username.
	keyUsername := store.HashBytes([]byte(username))
	hashedPassVal, err := s.db.Get(string(bucketAuthPassword), keyUsername)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}, "", ""
	}
	incomingHashed := hashPasswordSHA3(req.Password)
	if string(hashedPassVal) != incomingHashed {
		return api.Response{Success: false, Message: "Invalid credentials"}, "", ""
	}
	encryptedUUID, err := s.db.Get(string(bucketAuthUUID), keyUsername)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving UUID"}, "", ""
	}
	decryptedUUID, err := crypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return api.Response{Success: false, Message: "Error decrypting UUID"}, "", ""
	}
	accessToken, err := generateAccessToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating access token"}, "", ""
	}
	refreshToken, err := generateRefreshToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating refresh token"}, "", ""
	}
	// Hash the refresh token before storing.
	hashedRefresh := store.HashBytes([]byte(refreshToken))
	// Store in refresh bucket with key = HashBytes(decryptedUUID).
	hashedUUID := store.HashBytes([]byte(decryptedUUID))
	if err := s.db.Put("refresh", hashedUUID, hashedRefresh); err != nil {
		return api.Response{Success: false, Message: "Error saving refresh token"}, "", ""
	}
	// Return the decrypted username in Data so the client can set currentUser.
	return api.Response{Success: true, Message: "Login successful", Data: username}, accessToken, refreshToken
}

// refreshToken validates the provided refresh token, rotates it, and returns new tokens.
// It performs an atomic update: verifies the token hash, generates new tokens,
// and updates the stored refresh token hash.
func (s *serverImpl) refreshToken(req api.Request, providedRefreshToken string) (api.Response, string, string) {
	if req.Username == "" || providedRefreshToken == "" {
		return api.Response{Success: false, Message: "Missing credentials"}, "", ""
	}
	// Retrieve the user's decrypted UUID.
	decryptedUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}, "", ""
	}
	hashedUUID := store.HashBytes([]byte(decryptedUUID))
	storedHash, err := s.db.Get("refresh", hashedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Refresh token not found"}, "", ""
	}
	// Compute the hash of the incoming refresh token.
	incomingHash := store.HashBytes([]byte(providedRefreshToken))
	if hex.EncodeToString(storedHash) != hex.EncodeToString(incomingHash) {
		return api.Response{Success: false, Message: "Invalid refresh token"}, "", ""
	}
	// Validate the refresh token signature.
	_, err = validateJWTSignature(providedRefreshToken)
	if err != nil {
		return api.Response{Success: false, Message: "Expired or invalid refresh token"}, "", ""
	}
	// Generate new tokens.
	newAccessToken, err := generateAccessToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating new access token"}, "", ""
	}
	newRefreshToken, err := generateRefreshToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating new refresh token"}, "", ""
	}
	newHashedRefresh := store.HashBytes([]byte(newRefreshToken))
	// Atomically update the refresh token hash.
	if err := s.db.Put("refresh", hashedUUID, newHashedRefresh); err != nil {
		return api.Response{Success: false, Message: "Error updating refresh token"}, "", ""
	}
	return api.Response{Success: true, Message: "Tokens refreshed successfully"}, newAccessToken, newRefreshToken
}

// fetchData verifies the access token and returns the content from the "userdata" bucket.
func (s *serverImpl) fetchData(req api.Request, providedAccessToken string) api.Response {
	if req.Username == "" || providedAccessToken == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	decryptedUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	if !s.isAccessTokenValid(decryptedUUID, providedAccessToken) {
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
func (s *serverImpl) updateData(req api.Request, providedAccessToken string) api.Response {
	if req.Username == "" || providedAccessToken == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	decryptedUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	if !s.isAccessTokenValid(decryptedUUID, providedAccessToken) {
		return api.Response{Success: false, Message: "Invalid or expired access token"}
	}
	hashedUUID := store.HashBytes([]byte(decryptedUUID))
	if err := s.db.Put("userdata", hashedUUID, []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error updating user data"}
	}
	return api.Response{Success: true, Message: "User data updated"}
}

// logoutUser deletes the refresh token, invalidating the session.
func (s *serverImpl) logoutUser(req api.Request, providedRefreshToken string) api.Response {
	if req.Username == "" || providedRefreshToken == "" {
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

// userExists checks if the user exists in auth_password.
func (s *serverImpl) userExists(username string) (bool, error) {
	keyUsername := store.HashBytes([]byte(username))
	_, err := s.db.Get(string(bucketAuthPassword), keyUsername)
	if err != nil {
		if strings.Contains(err.Error(), "key not found") || strings.Contains(err.Error(), "bucket not found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isAccessTokenValid verifies the token signature and expiration using the user UUID.
func (s *serverImpl) isAccessTokenValid(userUUID, tokenString string) bool {
	token, err := validateJWTSignature(tokenString)
	if err != nil {
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

// lookupUUIDFromUsername retrieves the encrypted UUID from auth_uuid and decrypts it.
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
