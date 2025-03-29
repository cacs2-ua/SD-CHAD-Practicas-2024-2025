package server

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"prac/pkg/api"
	"prac/pkg/backup"
	"prac/pkg/crypto"
	"prac/pkg/logging"
	"prac/pkg/store"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
	"google.golang.org/api/drive/v2"
	"google.golang.org/api/option"
)

// Define bucket names (all names are now prefixed with "cheese")
var bucketAuthUUID = store.HashBytes([]byte("cheese_auth_uuid"))
var bucketAuthPassword = store.HashBytes([]byte("cheese_auth_password"))
var bucketAuthEmail = store.HashBytes([]byte("cheese_auth_email"))
var bucketAuthUsername = store.HashBytes([]byte("cheese_auth_username"))
var bucketAuthUsernameEmail = store.HashBytes([]byte("cheese_auth_username_email"))

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
func validateJWTSignature(tokenStr string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
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

// hashPasswordSHA3 hashes a password using SHA3-256 and returns a hex-encoded string.
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
	err = http.ListenAndServeTLS(":9200", "certs/server.crt", "certs/server.key", mux)
	return err
}

// apiHandler decodes the JSON request, dispatches the action, and returns the JSON response.
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

	// Extract access token from Authorization header.
	authHeader := r.Header.Get("Authorization")
	var providedAccessToken string
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			providedAccessToken = parts[1]
		}
	}

	// Extract refresh token from X-Refresh-Token header.
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
	case api.ActionBackup:
		res = s.backupDatabase()
	case api.ActionRestore:
		res = s.restoreDatabase(req)
	default:
		res = api.Response{Success: false, Message: "Unknown action"}
	}

	if newAccessToken != "" {
		w.Header().Set("Authorization", "Bearer "+newAccessToken)
	}
	if newRefreshToken != "" {
		w.Header().Set("X-Refresh-Token", "Bearer "+newRefreshToken)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// registerUser creates the following entries:
// 1. In cheese_auth_uuid: key = hash(email), value = encrypted(UUID)
// 2. In cheese_auth_email: key = hash(UUID), value = hash(email)
// 3. In cheese_auth_password: key = hash(UUID), value = hash(password)
// 4. In cheese_auth_username: key = hash(UUID), value = encrypted(username)
// 5. In cheese_auth_username_email: key = hash(username), value = hash(email)
// 6. In cheese_userdata: key = hash(UUID), value = "" (empty)
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
	// Check if username already exists using cheese_auth_username_email.
	keyUsername := store.HashBytes([]byte(req.Username))
	_, err := s.db.Get(string(bucketAuthUsernameEmail), keyUsername)
	if err == nil {
		return api.Response{Success: false, Message: "That username is already taken"}
	}
	// Check if email already exists using cheese_auth_uuid.
	keyEmail := store.HashBytes([]byte(req.Email))
	_, err = s.db.Get(string(bucketAuthUUID), keyEmail)
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
	// Hash the password.
	hashedPassword := hashPasswordSHA3(req.Password)
	// Encrypt the username.
	encryptedUsername, err := crypto.EncryptUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error encrypting username"}
	}

	// Store entries.
	keyUUID := store.HashBytes([]byte(userUUID))

	// In cheese_auth_uuid: key = hash(email), value = encryptedUUID.
	if err := s.db.Put(string(bucketAuthUUID), keyEmail, []byte(encryptedUUID)); err != nil {
		return api.Response{Success: false, Message: "Error saving encrypted UUID"}
	}
	// In cheese_auth_email: key = hash(UUID), value = hash(email).
	if err := s.db.Put(string(bucketAuthEmail), keyUUID, keyEmail); err != nil {
		return api.Response{Success: false, Message: "Error saving hashed email"}
	}
	// In cheese_auth_password: key = hash(UUID), value = hashedPassword.
	if err := s.db.Put(string(bucketAuthPassword), keyUUID, []byte(hashedPassword)); err != nil {
		return api.Response{Success: false, Message: "Error saving hashed password"}
	}
	// In cheese_auth_username: key = hash(UUID), value = encryptedUsername.
	if err := s.db.Put(string(bucketAuthUsername), keyUUID, []byte(encryptedUsername)); err != nil {
		return api.Response{Success: false, Message: "Error saving encrypted username"}
	}
	// In cheese_auth_username_email: key = hash(username), value = hash(email).
	if err := s.db.Put(string(bucketAuthUsernameEmail), keyUsername, keyEmail); err != nil {
		return api.Response{Success: false, Message: "Error saving username-email mapping"}
	}
	// In cheese_userdata: key = hash(UUID), value = "".
	if err := s.db.Put("cheese_userdata", keyUUID, []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error initializing user data"}
	}

	return api.Response{Success: true, Message: "User registered"}
}

// lookupUUIDFromUsername obtains the user's UUID by using the following chain:
// 1. Look up cheese_auth_username_email with key = hash(username) to obtain hashed email.
// 2. Look up cheese_auth_uuid with key = hashed email to get encrypted UUID and decrypt it.
func (s *serverImpl) lookupUUIDFromUsername(username string) (string, error) {
	keyUsername := store.HashBytes([]byte(username))
	hashedEmail, err := s.db.Get(string(bucketAuthUsernameEmail), keyUsername)
	if err != nil {
		return "", fmt.Errorf("User not found")
	}
	encryptedUUID, err := s.db.Get(string(bucketAuthUUID), hashedEmail)
	if err != nil {
		return "", fmt.Errorf("User not found")
	}
	decryptedUUID, err := crypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return "", fmt.Errorf("Error decrypting UUID")
	}
	return decryptedUUID, nil
}

// loginUser uses email and password to login.
// Steps:
// 1. Use email to retrieve encrypted UUID from cheese_auth_uuid.
// 2. Decrypt UUID.
// 3. Use UUID to get hashed password from cheese_auth_password and compare.
// 4. Use UUID to get encrypted username from cheese_auth_username and decrypt it.
// 5. Generate tokens.
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
	keyEmail := store.HashBytes([]byte(req.Email))
	encryptedUUID, err := s.db.Get(string(bucketAuthUUID), keyEmail)
	if err != nil {
		return api.Response{Success: false, Message: "Invalid credentials"}, "", ""
	}
	decryptedUUID, err := crypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return api.Response{Success: false, Message: "Error decrypting UUID"}, "", ""
	}
	keyUUID := store.HashBytes([]byte(decryptedUUID))
	hashedPassVal, err := s.db.Get(string(bucketAuthPassword), keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Invalid credentials"}, "", ""
	}
	incomingHashed := hashPasswordSHA3(req.Password)
	if string(hashedPassVal) != incomingHashed {
		return api.Response{Success: false, Message: "Invalid credentials"}, "", ""
	}
	encryptedUsername, err := s.db.Get(string(bucketAuthUsername), keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving username"}, "", ""
	}
	username, err := crypto.DecryptUsername(string(encryptedUsername))
	if err != nil {
		return api.Response{Success: false, Message: "Error decrypting username"}, "", ""
	}
	accessToken, err := generateAccessToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating access token"}, "", ""
	}
	refreshToken, err := generateRefreshToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating refresh token"}, "", ""
	}
	hashedRefresh := store.HashBytes([]byte(refreshToken))
	if err := s.db.Put("cheese_refresh", keyUUID, hashedRefresh); err != nil {
		return api.Response{Success: false, Message: "Error saving refresh token"}, "", ""
	}

	logging.Log("User " + username + " logged in successfully")

	return api.Response{Success: true, Message: "Login successful", Data: username}, accessToken, refreshToken
}

// refreshToken validates the provided refresh token and rotates it.
func (s *serverImpl) refreshToken(req api.Request, providedRefreshToken string) (api.Response, string, string) {
	if req.Username == "" || providedRefreshToken == "" {
		return api.Response{Success: false, Message: "Missing credentials"}, "", ""
	}
	decryptedUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}, "", ""
	}
	keyUUID := store.HashBytes([]byte(decryptedUUID))
	storedHash, err := s.db.Get("cheese_refresh", keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Refresh token not found"}, "", ""
	}
	incomingHash := store.HashBytes([]byte(providedRefreshToken))
	if hex.EncodeToString(storedHash) != hex.EncodeToString(incomingHash) {
		return api.Response{Success: false, Message: "Invalid refresh token"}, "", ""
	}
	_, err = validateJWTSignature(providedRefreshToken)
	if err != nil {
		return api.Response{Success: false, Message: "Expired or invalid refresh token"}, "", ""
	}
	newAccessToken, err := generateAccessToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating new access token"}, "", ""
	}
	newRefreshToken, err := generateRefreshToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating new refresh token"}, "", ""
	}
	newHashedRefresh := store.HashBytes([]byte(newRefreshToken))
	if err := s.db.Put("cheese_refresh", keyUUID, newHashedRefresh); err != nil {
		return api.Response{Success: false, Message: "Error updating refresh token"}, "", ""
	}
	return api.Response{Success: true, Message: "Tokens refreshed successfully"}, newAccessToken, newRefreshToken
}

// fetchData verifies the access token and returns the content from the "cheese_userdata" bucket.
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
	keyUUID := store.HashBytes([]byte(decryptedUUID))
	rawData, err := s.db.Get("cheese_userdata", keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving user data"}
	}
	return api.Response{
		Success: true,
		Message: "Private data for " + req.Username,
		Data:    string(rawData),
	}
}

// updateData updates the "cheese_userdata" bucket after verifying the access token.
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
	keyUUID := store.HashBytes([]byte(decryptedUUID))
	if err := s.db.Put("cheese_userdata", keyUUID, []byte(req.Data)); err != nil {
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
	keyUUID := store.HashBytes([]byte(decryptedUUID))
	if err := s.db.Delete("cheese_refresh", keyUUID); err != nil {
		return api.Response{Success: false, Message: "Error closing session"}
	}
	return api.Response{Success: true, Message: "Session closed successfully"}
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

// Funcion para hacer los backups
func (s *serverImpl) backupDatabase() api.Response {
	if err := backup.BackupDatabase(); err != nil {
		return api.Response{Success: false, Message: fmt.Sprintf("Error creating backup: %v", err)}
	}

	return api.Response{Success: true, Message: "Backup created successfully"}
}

// DownloadBackupFromGoogleDrive downloads a backup file from Google Drive.
func DownloadBackupFromGoogleDrive(fileID string, destinationPath string, credentialsPath string) error {
	ctx := context.Background()

	// Authenticate using the credentials JSON file.
	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return fmt.Errorf("error creating Google Drive service: %v", err)
	}

	// Get the file from Google Drive.
	resp, err := srv.Files.Get(fileID).Download()
	if err != nil {
		return fmt.Errorf("error downloading file from Google Drive: %v", err)
	}
	defer resp.Body.Close()

	// Create the destination file.
	destFile, err := os.Create(destinationPath)
	if err != nil {
		return fmt.Errorf("error creating destination file: %v", err)
	}
	defer destFile.Close()

	// Copy the file content to the destination file.
	if _, err := io.Copy(destFile, resp.Body); err != nil {
		return fmt.Errorf("error saving file to destination: %v", err)
	}

	return nil
}

// Funcion para recuperar los backups
func (s *serverImpl) restoreDatabase(req api.Request) api.Response {
	if req.Data == "" {
		return api.Response{Success: false, Message: "Missing backup file ID"}
	}

	backupFile := filepath.Join("backups", "restored_backup.db")
	dbPath := "data/server.db"

	// Descargar el archivo desde Google Drive.
	if err := backup.DownloadBackupFromGoogleDrive(req.Data, backupFile); err != nil {
		return api.Response{Success: false, Message: fmt.Sprintf("Error downloading backup: %v", err)}
	}

	// Cerrar la conexión actual a la base de datos.
	if err := s.db.Close(); err != nil {
		return api.Response{Success: false, Message: "Error closing database: " + err.Error()}
	}

	// Reemplazar el archivo de la base de datos con el backup descargado.
	if err := os.Rename(backupFile, dbPath); err != nil {
		return api.Response{Success: false, Message: "Error restoring backup: " + err.Error()}
	}

	// Reabrir la base de datos.
	newDB, err := store.NewStore("bbolt", dbPath)
	if err != nil {
		return api.Response{Success: false, Message: "Error reopening database: " + err.Error()}
	}
	s.db = newDB

	// Contar las entradas restauradas.
	lineCount, err := s.db.CountEntries()
	if err != nil {
		return api.Response{Success: false, Message: "Error counting database entries: " + err.Error()}
	}

	return api.Response{
		Success: true,
		Message: fmt.Sprintf("Backup restored successfully. Total entries restored: %d", lineCount),
	}
}
