package server

import (
	"bytes"
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
	"prac/pkg/functionalities"
	"prac/pkg/logging"
	"prac/pkg/store"
	"prac/pkg/token"
	"prac/pkg/utils"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"go.etcd.io/bbolt"
	"golang.org/x/crypto/sha3"
	"google.golang.org/api/drive/v2"
	"google.golang.org/api/option"
)

type ChatMessage struct {
	Sender string `json:"sender"`
	Packet string `json:"packet"` // JSON-encoded EncryptedPacket
}

// Global bucket names defined as plain strings to avoid double hashing.
var bucketAuthUUID = "cheese_auth_uuid"
var bucketAuthPassword = "cheese_auth_password"
var bucketAuthEmail = "cheese_auth_email"
var bucketAuthUsername = "cheese_auth_username"
var bucketAuthUsernameEmail = "cheese_auth_username_email"
var bucketAuthCypherHashedUUID = "cheese_auth_cipher_hashed_uuid"
var bucketMessages = "messages"

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
	// Set token signing key
	token.SetPrivateKey(privateKey)

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
	// Create the messages bucket if it does not exist
	bs, ok := db.(*store.BboltStore)
	if !ok {
		return fmt.Errorf("error asserting store to *BboltStore")
	}
	err = bs.DB.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(store.BucketName(bucketMessages))
		return err
	})
	if err != nil {
		return fmt.Errorf("error creating messages bucket: %v", err)
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
	case api.ActionPublicKeyLogin:
		// Initiate public key login; req.Email must be provided
		challenge, username, err := functionalities.InitiatePublicKeyLogin(s.db, req.Email)
		if err != nil {
			res = api.Response{Success: false, Message: err.Error()}
		} else {
			// Return a JSON object with the challenge and username
			dataObj := map[string]string{
				"challenge": challenge,
				"username":  username,
			}
			dataBytes, _ := json.Marshal(dataObj)
			res = api.Response{Success: true, Message: "Challenge generated", Data: string(dataBytes)}
		}
	case api.ActionPublicKeyLoginResponse:
		// Verify public key login response; req.Email and req.Data (signature) are required
		accessToken, refreshToken, err := functionalities.VerifyPublicKeyLogin(s.db, req.Email, req.Data)
		if err != nil {
			res = api.Response{Success: false, Message: err.Error()}
		} else {
			res = api.Response{Success: true, Message: "Public key login successful"}
			newAccessToken = accessToken
			newRefreshToken = refreshToken
		}
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
	// New messaging actions
	case api.ActionGetUsernames:
		res = s.handleGetUsernames(req)
	case api.ActionSendMessage:
		res = s.handleSendMessage(req)
	case api.ActionGetMessages:
		res = s.handleGetMessages(req)
	case api.ActionCreatePoll:
		res = s.handleCreatePoll(req, providedAccessToken)
	case api.ActionVoteInPoll:
		res = s.handleVoteInPoll(req, providedAccessToken)
	case api.ActionViewResults:
		res = s.handleViewResults(req, providedAccessToken)
	case api.ActionListPolls:
		res = s.handleListPolls(req, providedAccessToken)
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
// Additionally, it generates an RSA key pair for messaging.
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
	keyUsername := store.HashBytes([]byte(req.Username))
	_, err := s.db.Get(bucketAuthUsernameEmail, keyUsername)
	if err == nil {
		return api.Response{Success: false, Message: "That username is already taken"}
	}
	keyEmail := store.HashBytes([]byte(req.Email))
	_, err = s.db.Get(bucketAuthUUID, keyEmail)
	if err == nil {
		return api.Response{Success: false, Message: "Email already in use"}
	}

	userUUID := uuid.New().String()
	encryptedUUID, err := crypto.EncryptUUID(userUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error encrypting UUID"}
	}
	hashedPassword := hashPasswordSHA3(req.Password)
	encryptedUsername, err := crypto.EncryptUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error encrypting username"}
	}

	keyUUID := store.HashBytes([]byte(userUUID))

	encryptedCypher, err := crypto.EncryptServer(keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error encrypting cypher UUID: " + err.Error()}
	}
	if err := s.db.Put(bucketAuthCypherHashedUUID, keyUUID, []byte(encryptedCypher)); err != nil {
		return api.Response{Success: false, Message: "Error saving cypher UUID: " + err.Error()}
	}

	if err := s.db.Put(bucketAuthUUID, keyEmail, []byte(encryptedUUID)); err != nil {
		return api.Response{Success: false, Message: "Error saving encrypted UUID"}
	}
	if err := s.db.Put(bucketAuthEmail, keyUUID, keyEmail); err != nil {
		return api.Response{Success: false, Message: "Error saving hashed email"}
	}
	if err := s.db.Put(bucketAuthPassword, keyUUID, []byte(hashedPassword)); err != nil {
		return api.Response{Success: false, Message: "Error saving hashed password"}
	}
	if err := s.db.Put(bucketAuthUsername, keyUUID, []byte(encryptedUsername)); err != nil {
		return api.Response{Success: false, Message: "Error saving encrypted username"}
	}
	if err := s.db.Put(bucketAuthUsernameEmail, keyUsername, keyEmail); err != nil {
		return api.Response{Success: false, Message: "Error saving username-email mapping"}
	}
	if err := s.db.Put("cheese_userdata", keyUUID, []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error initializing user data"}
	}

	// Generate RSA key pair for messaging
	if err := functionalities.GenerateKeyPair(req.Username); err != nil {
		return api.Response{Success: false, Message: "Error generating key pair for messaging: " + err.Error()}
	}

	if err := functionalities.GenerateAuthKeyPair(s.db, req.Username, userUUID); err != nil {
		return api.Response{Success: false, Message: "Error generating auth key pair: " + err.Error()}
	}

	return api.Response{Success: true, Message: "User registered"}
}

// lookupUUIDFromUsername obtains the user's UUID by using the following chain:
// 1. Look up cheese_auth_username_email with key = hash(username) to obtain hashed email.
// 2. Look up cheese_auth_uuid with key = hashed email to get encrypted UUID and decrypt it.
func (s *serverImpl) lookupUUIDFromUsername(username string) (string, error) {
	keyUsername := store.HashBytes([]byte(username))
	hashedEmail, err := s.db.Get(bucketAuthUsernameEmail, keyUsername)
	if err != nil {
		return "", fmt.Errorf("User not found")
	}
	encryptedUUID, err := s.db.Get(bucketAuthUUID, hashedEmail)
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
	encryptedUUID, err := s.db.Get(bucketAuthUUID, keyEmail)
	if err != nil {
		return api.Response{Success: false, Message: "Invalid credentials"}, "", ""
	}
	decryptedUUID, err := crypto.DecryptUUID(string(encryptedUUID))
	if err != nil {
		return api.Response{Success: false, Message: "Error decrypting UUID"}, "", ""
	}
	keyUUID := store.HashBytes([]byte(decryptedUUID))
	hashedPassVal, err := s.db.Get(bucketAuthPassword, keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Invalid credentials"}, "", ""
	}
	incomingHashed := hashPasswordSHA3(req.Password)
	if string(hashedPassVal) != incomingHashed {
		return api.Response{Success: false, Message: "Invalid credentials"}, "", ""
	}
	encryptedUsername, err := s.db.Get(bucketAuthUsername, keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving username"}, "", ""
	}
	username, err := crypto.DecryptUsername(string(encryptedUsername))
	if err != nil {
		return api.Response{Success: false, Message: "Error decrypting username"}, "", ""
	}
	accessToken, err := token.GenerateAccessToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating access token"}, "", ""
	}
	refreshToken, err := token.GenerateRefreshToken(decryptedUUID)
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
	newAccessToken, err := token.GenerateAccessToken(decryptedUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating new access token"}, "", ""
	}
	newRefreshToken, err := token.GenerateRefreshToken(decryptedUUID)
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

// backupDatabase calls the backup package to perform a backup.
func (s *serverImpl) backupDatabase() api.Response {
	if err := backup.BackupDatabase(); err != nil {
		return api.Response{Success: false, Message: fmt.Sprintf("Error creating backup: %v", err)}
	}
	return api.Response{Success: true, Message: "Backup created successfully"}
}

// DownloadBackupFromGoogleDrive downloads a backup file from Google Drive.
func DownloadBackupFromGoogleDrive(fileID string, destinationPath string, credentialsPath string) error {
	ctx := context.Background()
	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return fmt.Errorf("error creating Google Drive service: %v", err)
	}
	resp, err := srv.Files.Get(fileID).Download()
	if err != nil {
		return fmt.Errorf("error downloading file from Google Drive: %v", err)
	}
	defer resp.Body.Close()
	destFile, err := os.Create(destinationPath)
	if err != nil {
		return fmt.Errorf("error creating destination file: %v", err)
	}
	defer destFile.Close()
	if _, err := io.Copy(destFile, resp.Body); err != nil {
		return fmt.Errorf("error saving file to destination: %v", err)
	}
	return nil
}

// restoreDatabase downloads a backup, replaces the current database file, and reopens the store.
func (s *serverImpl) restoreDatabase(req api.Request) api.Response {
	if req.Data == "" {
		return api.Response{Success: false, Message: "Missing backup file ID"}
	}
	backupFile := filepath.Join("backups", "restored_backup.db")
	dbPath := "data/server.db"
	if err := backup.DownloadBackupFromGoogleDrive(req.Data, backupFile); err != nil {
		return api.Response{Success: false, Message: fmt.Sprintf("Error downloading backup: %v", err)}
	}
	if err := s.db.Close(); err != nil {
		return api.Response{Success: false, Message: "Error closing database: " + err.Error()}
	}
	if err := os.Rename(backupFile, dbPath); err != nil {
		return api.Response{Success: false, Message: "Error restoring backup: " + err.Error()}
	}
	newDB, err := store.NewStore("bbolt", dbPath)
	if err != nil {
		return api.Response{Success: false, Message: "Error reopening database: " + err.Error()}
	}
	s.db = newDB
	lineCount, err := s.db.CountEntries()
	if err != nil {
		return api.Response{Success: false, Message: "Error counting database entries: " + err.Error()}
	}
	return api.Response{
		Success: true,
		Message: fmt.Sprintf("Backup restored successfully. Total entries restored: %d", lineCount),
	}
}

// ---------------------------
// New Messaging Actions
// ---------------------------

// handleGetUsernames retrieves all usernames from the "cheese_auth_username" bucket.
// It decrypts each stored username using crypto.DecryptUsername.
func (s *serverImpl) handleGetUsernames(req api.Request) api.Response {
	bucketName := bucketAuthUsername
	var usernames []string
	bs, ok := s.db.(*store.BboltStore)
	if !ok {
		return api.Response{Success: false, Message: "Store type assertion failed"}
	}
	bName := store.BucketName(bucketName)
	err := bs.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bName)
		if b == nil {
			return fmt.Errorf("bucket not found")
		}
		return b.ForEach(func(k, v []byte) error {
			// First decrypt with DecryptServer (to remove the outer encryption)
			serverDecrypted, err := crypto.DecryptServer(v)
			if err != nil {
				// Skip entries that cannot be decrypted by server key
				return nil
			}
			// Now decrypt with DecryptUsername to get the actual username
			decrypted, err := crypto.DecryptUsername(string(serverDecrypted))
			if err != nil {
				// Skip entries that cannot be decrypted
				return nil
			}
			usernames = append(usernames, decrypted)
			return nil
		})
	})
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving usernames"}
	}
	data, err := json.Marshal(usernames)
	if err != nil {
		return api.Response{Success: false, Message: "Error encoding usernames"}
	}
	return api.Response{Success: true, Message: "Usernames retrieved", Data: string(data)}
}

// handleSendMessage stores an encrypted message in the "messages" bucket.
// It expects req.Sender (the sender's username), req.Username (the recipient), and req.Data (the encrypted packet as JSON).
func (s *serverImpl) handleSendMessage(req api.Request) api.Response {
	sender := req.Sender
	recipient := req.Username
	if sender == "" || recipient == "" || req.Data == "" {
		return api.Response{Success: false, Message: "Missing sender, recipient, or data"}
	}

	// Get the encrypted hashed UUID for sender and recipient using the new utility function.
	encryptedUUIDSender, err := utils.GetEncryptedHashedUUIDFromUsername(s.db, sender)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving encrypted UUID for sender: " + err.Error()}
	}
	encryptedUUIDRecipient, err := utils.GetEncryptedHashedUUIDFromUsername(s.db, recipient)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving encrypted UUID for recipient: " + err.Error()}
	}

	// Create the conversation ID by lexicographically sorting the two encrypted UUIDs.
	var convID string
	if encryptedUUIDSender < encryptedUUIDRecipient {
		convID = fmt.Sprintf("%s:%s", encryptedUUIDSender, encryptedUUIDRecipient)
	} else {
		convID = fmt.Sprintf("%s:%s", encryptedUUIDRecipient, encryptedUUIDSender)
	}

	// Append the current timestamp.
	timestamp := time.Now().UnixNano()
	messageKey := fmt.Sprintf("%s:%d", convID, timestamp)

	// Wrap the incoming packet (req.Data) with the sender identity.
	chatMsg := ChatMessage{
		Sender: sender,
		Packet: req.Data,
	}
	chatMsgBytes, err := json.Marshal(chatMsg)
	if err != nil {
		return api.Response{Success: false, Message: "Error encoding chat message: " + err.Error()}
	}

	// Store the message using the new conversation key.
	if err := s.db.Put(bucketMessages, []byte(messageKey), chatMsgBytes); err != nil {
		return api.Response{Success: false, Message: "Error storing message: " + err.Error()}
	}
	return api.Response{Success: true, Message: "Message stored"}
}

// handleGetMessages retrieves all messages for a conversation between req.Sender and req.Username.
func (s *serverImpl) handleGetMessages(req api.Request) api.Response {
	sender := req.Sender
	partner := req.Username
	if sender == "" || partner == "" {
		return api.Response{Success: false, Message: "Missing sender or conversation partner"}
	}

	// Get the encrypted hashed UUID for both the sender and the partner.
	encryptedUUIDSender, err := utils.GetEncryptedHashedUUIDFromUsername(s.db, sender)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving encrypted UUID for sender: " + err.Error()}
	}
	encryptedUUIDPartner, err := utils.GetEncryptedHashedUUIDFromUsername(s.db, partner)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving encrypted UUID for partner: " + err.Error()}
	}

	// Create the conversation ID by lexicographically sorting the encrypted UUIDs.
	var convID string
	if encryptedUUIDSender < encryptedUUIDPartner {
		convID = fmt.Sprintf("%s:%s", encryptedUUIDSender, encryptedUUIDPartner)
	} else {
		convID = fmt.Sprintf("%s:%s", encryptedUUIDPartner, encryptedUUIDSender)
	}

	// Use convID as a prefix to retrieve all messages for the conversation.
	prefix := []byte(convID + ":")
	var chatMessages []ChatMessage
	bs, ok := s.db.(*store.BboltStore)
	if !ok {
		return api.Response{Success: false, Message: "Store type assertion failed"}
	}
	bucketName := store.BucketName(bucketMessages)
	err = bs.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return fmt.Errorf("messages bucket not found")
		}
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var chatMsg ChatMessage
			// The stored value is encrypted with EncryptServer; decrypt it first.
			decryptedVal, err := crypto.DecryptServer(v)
			if err != nil {
				continue // Skip if decryption fails.
			}
			if err := json.Unmarshal(decryptedVal, &chatMsg); err != nil {
				continue
			}
			chatMessages = append(chatMessages, chatMsg)
		}
		return nil
	})
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving messages: " + err.Error()}
	}
	data, err := json.Marshal(chatMessages)
	if err != nil {
		return api.Response{Success: false, Message: "Error encoding messages"}
	}
	return api.Response{Success: true, Message: "Messages retrieved", Data: string(data)}
}
