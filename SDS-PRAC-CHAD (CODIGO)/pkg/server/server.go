package server

import (
	"bytes"
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
)

type ChatMessage struct {
	Sender string `json:"sender"`
	Packet string `json:"packet"`
}

var bucketAuthUUID = "cheese_auth_uuid"
var bucketAuthPassword = "cheese_auth_password"
var bucketAuthEmail = "cheese_auth_email"
var bucketAuthUsername = "cheese_auth_username"
var bucketAuthUsernameEmail = "cheese_auth_username_email"
var bucketUserGroup = "cheese_user_group"
var bucketAuthCypherHashedUUID = "cheese_auth_cipher_hashed_uuid"
var bucketMessages = "messages"
var bucketBannedUsers = "cheese_banned_users"

var (
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
)

func init() {
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
	token.SetPrivateKey(privateKey)

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

func hashPasswordSHA3(password string) string {
	hasher := sha3.New256()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

type serverImpl struct {
	db  store.Store
	log *log.Logger
}

func Run() error {
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error opening database: %v", err)
	}

	if err := createDefaultUsers(db); err != nil {
		log.Printf("Error creating default users: %v", err)
	}

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

	srv.vaciabd(bs)
	srv.seedPolls()

	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))
	err = http.ListenAndServeTLS(":9200", "certs/server.crt", "certs/server.key", mux)
	return err
}

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

	authHeader := r.Header.Get("Authorization")
	var providedAccessToken string
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			providedAccessToken = parts[1]
		}
	}

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
		challenge, username, role, err := functionalities.InitiatePublicKeyLogin(s.db, req.Email)
		if err != nil {
			res = api.Response{Success: false, Message: err.Error()}
		} else {
			dataObj := map[string]string{
				"challenge": challenge,
				"username":  username,
				"role":      role,
			}
			dataBytes, _ := json.Marshal(dataObj)
			res = api.Response{Success: true, Message: "Challenge generated", Data: string(dataBytes)}
		}
	case api.ActionPublicKeyLoginResponse:
		accessToken, refreshToken, role, group, err := functionalities.VerifyPublicKeyLogin(s.db, req.Email, req.Data)
		responseData := map[string]string{
			"username":   req.Email,
			"role":       string(role),
			"user_group": string(group),
		}
		responseJSON, _ := json.Marshal(responseData)

		if err != nil {
			res = api.Response{Success: false, Message: err.Error()}
		} else {

			res = api.Response{Success: true, Message: "Public key login successful", Data: string(responseJSON)}
			newAccessToken = accessToken
			newRefreshToken = refreshToken
			logging.Log("Public key login successful for user: " + req.Email)

		}
	case api.ActionRefresh:
		res, newAccessToken, newRefreshToken = s.refreshToken(req, providedRefreshToken)
	case api.ActionFetchData:
		res = s.fetchData(req, providedAccessToken)
	case api.ActionUpdateData:
		res = s.updateData(req, providedAccessToken)
	case api.ActionModifyUserRole:
		res = s.handleModifyUserRole(req, providedAccessToken)
	case api.ActionFetchUserRole:
		res = s.handleFetchUserRole(req)
	case api.ActionLogout:
		res = s.logoutUser(req, providedRefreshToken)
	case api.ActionBackup:
		res = s.backupDatabase()
	case api.ActionRestore:
		res = s.restoreDatabase(req)
	case api.ActionGetUsernames:
		res = s.handleGetUsernames(req)
	case api.ActionSendMessage:
		res = s.handleSendMessage(req)
	case api.ActionGetMessages:
		res = s.handleGetMessages(req)
	case api.ActionCreatePoll:
		res = s.handleCreatePoll(req, providedAccessToken)
	case api.ActionModifyPoll:
		res = s.handleModifyPoll(req, providedAccessToken)
	case api.ActionVoteInPoll:
		res = s.handleVoteInPoll(req, providedAccessToken)
	case api.ActionViewResults:
		res = s.handleViewResults(req, providedAccessToken)
	case api.ActionListPolls:
		res = s.handleListPolls(req, providedAccessToken)
	case api.ActionBanUser:
		res = s.banUser(req)
	case api.ActionUnbanUser:
		res = s.unbanUser(req)
	case api.ActionCheckBanStatus:
		res = s.checkUserBanStatus(req)
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

	if res.Success {
		// logging.Log(fmt.Sprintf("Acción %s ejecutada con éxito para usuario %s", req.Action, req.Username))
	} else {
		// logging.Log(fmt.Sprintf("Acción %s falló para usuario %s: %s", req.Action, req.Username, res.Message))
	}

	json.NewEncoder(w).Encode(res)
}

func (s *serverImpl) registerUser(req api.Request) api.Response {
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)
	req.UserGroup = strings.TrimSpace(req.UserGroup)

	if req.Username == "" || req.Password == "" || req.Email == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}

	if req.UserGroup == "admin" || req.UserGroup == "moderator" {
		return api.Response{Success: false, Message: "User group cannot be 'admin' nor 'moderator'"}
	}

	if req.UserGroup == "" {
		return api.Response{Success: false, Message: "User group must not be empty"}
	}

	if len(req.UserGroup) < 4 {
		return api.Response{Success: false, Message: "User group must have at least 4 characters"}
	}

	if len(req.Username) < 4 {
		return api.Response{Success: false, Message: "Username must have at least 4 characters"}
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
	if err := s.db.Put(bucketUserGroup, keyUUID, []byte(req.UserGroup)); err != nil {
		return api.Response{Success: false, Message: "Error saving user group: " + err.Error()}
	}

	// Assign role "normal" for a user registering using the default registration
	if err := s.db.Put("cheese_roles", keyUUID, []byte("normal")); err != nil {
		return api.Response{Success: false, Message: "Error saving user role: " + err.Error()}
	}

	// Generate RSA key pair for messaging
	if err := functionalities.GenerateKeyPair(req.Username); err != nil {
		return api.Response{Success: false, Message: "Error generating key pair for messaging: " + err.Error()}
	}

	if err := functionalities.GenerateAuthKeyPair(s.db, req.Username, userUUID); err != nil {
		return api.Response{Success: false, Message: "Error generating auth key pair: " + err.Error()}
	}
	role, err := s.db.Get("cheese_roles", keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving user role"}
	}

	responseData := map[string]string{
		"username":   req.Username,
		"role":       string(role),
		"user_group": req.UserGroup,
	}

	responseJSON, _ := json.Marshal(responseData)

	logging.Log("Usuario registrado: " + req.Username)

	return api.Response{Success: true, Message: "User registered", Data: string(responseJSON)}
}

func createDefaultUsers(db store.Store) error {
	// Define default users data in an array of structs (email, username, password, role)
	defaultUsers := []struct {
		email     string
		username  string
		password  string
		role      string
		userGroup string
	}{
		{"admin1@gmail.com", "admin1", "admin1admin1", "admin", "admin"},
		{"moderator1@gmail.com", "moderator1", "moderator1", "moderator", "moderator"},

		{"programador1@gmail.com", "programador1", "programador1", "normal", "programadores"},
		{"estudiante1@gmail.com", "estudiante1", "estudiante1", "normal", "estudiantes"},
		{"deportista1@gmail.com", "deportista1", "deportista1", "normal", "deportistas"},
		{"chadorador1@gmail.com", "chadorador1", "chadorador1", "normal", "oradores"},
	}

	for _, user := range defaultUsers {
		keyEmail := store.HashBytes([]byte(user.email))
		if _, err := db.Get("cheese_auth_uuid", keyEmail); err == nil {
			continue
		}

		userUUID := uuid.New().String()
		encryptedUUID, err := crypto.EncryptUUID(userUUID)
		if err != nil {
			return fmt.Errorf("error encrypting UUID for %s: %v", user.email, err)
		}

		hasher := sha3.New256()
		hasher.Write([]byte(user.password))
		hashedPassword := hex.EncodeToString(hasher.Sum(nil))

		encryptedUsername, err := crypto.EncryptUsername(user.username)
		if err != nil {
			return fmt.Errorf("error encrypting username for %s: %v", user.email, err)
		}

		keyUUID := store.HashBytes([]byte(userUUID))
		keyUsername := store.HashBytes([]byte(user.username))

		encryptedCypher, err := crypto.EncryptServer(keyUUID)
		if err != nil {
			return fmt.Errorf("error encrypting cypher UUID for %s: %v", user.email, err)
		}
		if err := db.Put("cheese_auth_cipher_hashed_uuid", keyUUID, []byte(encryptedCypher)); err != nil {
			return fmt.Errorf("error saving cypher UUID for %s: %v", user.email, err)
		}
		if err := db.Put("cheese_auth_uuid", keyEmail, []byte(encryptedUUID)); err != nil {
			return fmt.Errorf("error saving encrypted UUID for %s: %v", user.email, err)
		}
		if err := db.Put("cheese_auth_email", keyUUID, keyEmail); err != nil {
			return fmt.Errorf("error saving hashed email for %s: %v", user.email, err)
		}
		if err := db.Put("cheese_auth_password", keyUUID, []byte(hashedPassword)); err != nil {
			return fmt.Errorf("error saving hashed password for %s: %v", user.email, err)
		}
		if err := db.Put("cheese_auth_username", keyUUID, []byte(encryptedUsername)); err != nil {
			return fmt.Errorf("error saving encrypted username for %s: %v", user.email, err)
		}
		if err := db.Put("cheese_auth_username_email", keyUsername, keyEmail); err != nil {
			return fmt.Errorf("error saving username-email mapping for %s: %v", user.email, err)
		}
		if err := db.Put("cheese_userdata", keyUUID, []byte("")); err != nil {
			return fmt.Errorf("error initializing user data for %s: %v", user.email, err)
		}
		if err := db.Put("cheese_roles", keyUUID, []byte(user.role)); err != nil {
			return fmt.Errorf("error saving role for %s: %v", user.email, err)
		}

		if err := db.Put(bucketUserGroup, keyUUID, []byte(user.userGroup)); err != nil {
			return fmt.Errorf("error saving user group for %s: %v", user.email, err)
		}

		if err := functionalities.GenerateKeyPair(user.username); err != nil {
			return fmt.Errorf("error generating key pair for default user %s: %v", user.email, err)
		}
		if err := functionalities.GenerateAuthKeyPair(db, user.username, userUUID); err != nil {
			return fmt.Errorf("error generating auth key pair for default user %s: %v", user.email, err)
		}
	}
	return nil
}

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
	if s.isUserBanned(decryptedUUID) {
		return api.Response{Success: false, Message: "User is banned"}, "", ""
	}
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

	role, err := s.db.Get("cheese_roles", keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving user role"}, "", ""
	}

	logging.Log("User " + username + " logged in successfully")

	userGroupBytes, _ := s.db.Get(bucketUserGroup, keyUUID)

	responseData := map[string]string{
		"username":   username,
		"role":       string(role),
		"user_group": string(userGroupBytes),
	}

	responseJSON, _ := json.Marshal(responseData)

	logging.Log("User " + username + " logged in successfully")

	return api.Response{Success: true, Message: "Login successful", Data: string(responseJSON)}, accessToken, refreshToken
}

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

	// logging.Log("Tokens refreshed for user: " + req.Username)

	return api.Response{Success: true, Message: "Tokens refreshed successfully"}, newAccessToken, newRefreshToken
}

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

	// logging.Log("Data readed/updated for the user: " + req.Username)

	return api.Response{
		Success: true,
		Message: "Private data for " + req.Username,
		Data:    string(rawData),
	}
}

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

	logging.Log("This user has logged out: " + req.Username)

	return api.Response{Success: true, Message: "Session closed successfully"}

}

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

func (s *serverImpl) backupDatabase() api.Response {
	if err := backup.BackupDatabase(); err != nil {
		return api.Response{Success: false, Message: fmt.Sprintf("Error creating backup: %v", err)}
	}
	return api.Response{Success: true, Message: "Backup created successfully"}
}

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

	logging.Log(fmt.Sprintf("Backup restored for the user %s", req.Username))

	return api.Response{
		Success: true,
		Message: fmt.Sprintf("Backup restored successfully. Total entries restored: %d", lineCount),
	}
}

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
			serverDecrypted, err := crypto.DecryptServer(v)
			if err != nil {
				return nil
			}
			decrypted, err := crypto.DecryptUsername(string(serverDecrypted))
			if err != nil {
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

func (s *serverImpl) handleSendMessage(req api.Request) api.Response {
	sender := req.Sender
	recipient := req.Username
	if sender == "" || recipient == "" || req.Data == "" {
		return api.Response{Success: false, Message: "Missing sender, recipient, or data"}
	}

	encryptedUUIDSender, err := utils.GetEncryptedHashedUUIDFromUsername(s.db, sender)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving encrypted UUID for sender: " + err.Error()}
	}
	encryptedUUIDRecipient, err := utils.GetEncryptedHashedUUIDFromUsername(s.db, recipient)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving encrypted UUID for recipient: " + err.Error()}
	}

	var convID string
	if encryptedUUIDSender < encryptedUUIDRecipient {
		convID = fmt.Sprintf("%s:%s", encryptedUUIDSender, encryptedUUIDRecipient)
	} else {
		convID = fmt.Sprintf("%s:%s", encryptedUUIDRecipient, encryptedUUIDSender)
	}

	timestamp := time.Now().UnixNano()
	messageKey := fmt.Sprintf("%s:%d", convID, timestamp)

	chatMsg := ChatMessage{
		Sender: sender,
		Packet: req.Data,
	}
	chatMsgBytes, err := json.Marshal(chatMsg)
	if err != nil {
		return api.Response{Success: false, Message: "Error encoding chat message: " + err.Error()}
	}

	if err := s.db.Put(bucketMessages, []byte(messageKey), chatMsgBytes); err != nil {
		return api.Response{Success: false, Message: "Error storing message: " + err.Error()}
	}

	// logging.Log(fmt.Sprintf("Mensaje enviado de %s a %s", req.Sender, req.Username))

	return api.Response{Success: true, Message: "Message stored"}
}

func (s *serverImpl) handleGetMessages(req api.Request) api.Response {
	sender := req.Sender
	partner := req.Username
	if sender == "" || partner == "" {
		return api.Response{Success: false, Message: "Missing sender or conversation partner"}
	}

	encryptedUUIDSender, err := utils.GetEncryptedHashedUUIDFromUsername(s.db, sender)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving encrypted UUID for sender: " + err.Error()}
	}
	encryptedUUIDPartner, err := utils.GetEncryptedHashedUUIDFromUsername(s.db, partner)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving encrypted UUID for partner: " + err.Error()}
	}

	var convID string
	if encryptedUUIDSender < encryptedUUIDPartner {
		convID = fmt.Sprintf("%s:%s", encryptedUUIDSender, encryptedUUIDPartner)
	} else {
		convID = fmt.Sprintf("%s:%s", encryptedUUIDPartner, encryptedUUIDSender)
	}

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
			decryptedVal, err := crypto.DecryptServer(v)
			if err != nil {
				continue
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

	// logging.Log(fmt.Sprintf("Mensajes recuperados para conversación %s↔%s", req.Sender, req.Username))

	return api.Response{Success: true, Message: "Messages retrieved", Data: string(data)}
}

func (s *serverImpl) banUser(req api.Request) api.Response {
	if req.Username == "" {
		return api.Response{Success: false, Message: "Missing username"}
	}

	userUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}

	keyUUID := store.HashBytes([]byte(userUUID))
	role, err := s.db.Get("cheese_roles", keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving user role"}
	}

	if string(role) == "admin" || string(role) == "moderator" {
		return api.Response{Success: false, Message: "Cannot ban users with admin or moderator roles"}
	}

	if err := s.db.Put(bucketBannedUsers, keyUUID, []byte("banned")); err != nil {
		return api.Response{Success: false, Message: "Error banning user: " + err.Error()}
	}

	logging.Log(fmt.Sprintf("User banned: %s", req.Username))

	return api.Response{Success: true, Message: "User banned successfully"}
}

func (s *serverImpl) unbanUser(req api.Request) api.Response {
	if req.Username == "" {
		return api.Response{Success: false, Message: "Missing username"}
	}
	userUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}
	keyUUID := store.HashBytes([]byte(userUUID))
	if err := s.db.Delete(bucketBannedUsers, keyUUID); err != nil {
		return api.Response{Success: false, Message: "Error unbanning user: " + err.Error()}
	}

	logging.Log(fmt.Sprintf("User unbanned: %s", req.Username))

	return api.Response{Success: true, Message: "User unbanned successfully"}
}

func (s *serverImpl) isUserBanned(userUUID string) bool {
	keyUUID := store.HashBytes([]byte(userUUID))
	_, err := s.db.Get(bucketBannedUsers, keyUUID)
	return err == nil
}

func (s *serverImpl) checkUserBanStatus(req api.Request) api.Response {
	if req.Username == "" {
		return api.Response{Success: false, Message: "Missing username"}
	}
	userUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}
	keyUUID := store.HashBytes([]byte(userUUID))
	_, err = s.db.Get(bucketBannedUsers, keyUUID)
	if err == nil {
		return api.Response{Success: true, Message: "User is banned"}
	}
	return api.Response{Success: true, Message: "User is not banned"}
}

func (s *serverImpl) handleFetchUserRole(req api.Request) api.Response {
	if req.Username == "" {
		return api.Response{Success: false, Message: "Missing username"}
	}

	userUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}

	keyUUID := store.HashBytes([]byte(userUUID))
	currentRole, err := s.db.Get("cheese_roles", keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving user role"}
	}

	return api.Response{Success: true, Message: "User role retrieved", Data: string(currentRole)}
}

func (s *serverImpl) handleModifyUserRole(req api.Request, providedAccessToken string) api.Response {
	if req.Username == "" || req.Data == "" {
		return api.Response{Success: false, Message: "Missing username or role"}
	}

	newRole := req.Data
	if newRole != "normal" && newRole != "moderator" {
		return api.Response{Success: false, Message: "Invalid role"}
	}

	userUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}

	keyUUID := store.HashBytes([]byte(userUUID))
	currentRole, err := s.db.Get("cheese_roles", keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving user role"}
	}

	if string(currentRole) == "admin" {
		return api.Response{Success: false, Message: "Cannot modify the role of an admin"}
	}

	if string(currentRole) == newRole {
		return api.Response{Success: false, Message: fmt.Sprintf("The user already has the role '%s'", newRole)}
	}

	if err := s.db.Put("cheese_roles", keyUUID, []byte(newRole)); err != nil {
		return api.Response{Success: false, Message: "Error updating user role"}
	}

	logging.Log(fmt.Sprintf("User role modified: %s -> %s", req.Username, newRole))

	return api.Response{Success: true, Message: "User role updated successfully"}
}
