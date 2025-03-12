package server

import (
	"crypto/rsa"
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
	"prac/pkg/store"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

// init loads the RSA private and public keys from the "keys" folder.
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
	// First try to parse as PKCS1
	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// If that fails, try PKCS8
		keyInterface, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			log.Fatalf("Error parsing private key: %v", err2)
		}
		var ok bool
		privateKey, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			log.Fatal("Private key is not of type RSA")
		}
	} else {
		privateKey = parsedKey
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
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing public key: %v", err)
	}
	var ok bool
	publicKey, ok = pub.(*rsa.PublicKey)
	if !ok {
		log.Fatal("Public key is not of type RSA")
	}
}

// generateAccessToken creates an access JWT for the given username with short expiration (30 seconds).
func generateAccessToken(username string) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: time.Now().Add(30 * time.Second).Unix(), // expiration set to 30 seconds for debugging
		IssuedAt:  time.Now().Unix(),
		Issuer:    "prac-server",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// generateRefreshToken creates a refresh JWT for the given username with longer expiration (7 days).
func generateRefreshToken(username string) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Issuer:    "prac-server",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
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
	// Open the database using the bbolt engine.
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error opening database: %v", err)
	}

	// Create our server with a logger with prefix 'srv'.
	srv := &serverImpl{
		db:  db,
		log: log.New(os.Stdout, "[srv] ", log.LstdFlags),
	}

	// Ensure the database is closed when the function ends.
	defer srv.db.Close()

	// Create a new ServeMux and associate /api with our apiHandler.
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Start the HTTPS server on port 8080 using TLS.
	err = http.ListenAndServeTLS(":8080", "certs/server.crt", "certs/server.key", mux)
	return err
}

// apiHandler decodes the JSON request, dispatches it to the corresponding function,
// and returns the JSON response.
func (s *serverImpl) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode the request into an api.Request structure.
	var req api.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Dispatch based on the requested action.
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

	// Send the response in JSON format.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// registerUser registers a new user if they do not exist.
// It hashes the password using bcrypt and stores it in the 'auth' namespace.
// It also creates an empty entry in 'userdata' for the user.
func (s *serverImpl) registerUser(req api.Request) api.Response {
	// Basic validation.
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}

	// Check if the user already exists in 'auth'.
	exists, err := s.userExists(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error checking user"}
	}
	if exists {
		return api.Response{Success: false, Message: "User already exists"}
	}

	// Hash the password using bcrypt.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return api.Response{Success: false, Message: "Error hashing password"}
	}

	// Store the hashed password in the 'auth' namespace.
	if err := s.db.Put("auth", []byte(req.Username), hashedPassword); err != nil {
		return api.Response{Success: false, Message: "Error saving credentials"}
	}

	// Create an empty entry for user data in 'userdata'.
	if err := s.db.Put("userdata", []byte(req.Username), []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error initializing user data"}
	}

	return api.Response{Success: true, Message: "User registered"}
}

// loginUser validates credentials in the 'auth' namespace and generates access and refresh tokens.
func (s *serverImpl) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}

	// Retrieve the stored hashed password from 'auth'.
	storedHash, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}

	// Compare the stored hash with the provided password.
	if err := bcrypt.CompareHashAndPassword(storedHash, []byte(req.Password)); err != nil {
		return api.Response{Success: false, Message: "Invalid credentials"}
	}

	// Generate an access token (30 seconds expiration for debugging).
	accessToken, err := generateAccessToken(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating access token"}
	}

	// Generate a refresh token (7 days expiration).
	refreshToken, err := generateRefreshToken(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating refresh token"}
	}

	// Store the refresh token in the 'refresh' namespace.
	if err := s.db.Put("refresh", []byte(req.Username), []byte(refreshToken)); err != nil {
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

	// Retrieve stored refresh token from 'refresh' namespace.
	storedToken, err := s.db.Get("refresh", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Refresh token not found"}
	}
	if string(storedToken) != req.RefreshToken {
		return api.Response{Success: false, Message: "Invalid refresh token"}
	}

	// Optionally, verify the refresh token's expiration.
	token, err := jwt.Parse(req.RefreshToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		return api.Response{Success: false, Message: "Expired or invalid refresh token"}
	}

	// Generate new tokens.
	newAccessToken, err := generateAccessToken(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating new access token"}
	}
	newRefreshToken, err := generateRefreshToken(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error generating new refresh token"}
	}

	// Update the refresh token in the 'refresh' namespace (token rotation).
	if err := s.db.Put("refresh", []byte(req.Username), []byte(newRefreshToken)); err != nil {
		return api.Response{Success: false, Message: "Error updating refresh token"}
	}

	return api.Response{
		Success:      true,
		Message:      "Tokens refreshed successfully",
		Token:        newAccessToken,
		RefreshToken: newRefreshToken,
	}
}

// fetchData verifies the access token and returns the content from the 'userdata' namespace.
func (s *serverImpl) fetchData(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if !s.isAccessTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired access token"}
	}

	// Retrieve the user data from 'userdata'.
	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error retrieving user data"}
	}

	return api.Response{
		Success: true,
		Message: "Private data for " + req.Username,
		Data:    string(rawData),
	}
}

// updateData updates the content of 'userdata' after verifying the access token.
func (s *serverImpl) updateData(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if !s.isAccessTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired access token"}
	}

	// Update the user data in 'userdata'.
	if err := s.db.Put("userdata", []byte(req.Username), []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error updating user data"}
	}

	return api.Response{Success: true, Message: "User data updated"}
}

// logoutUser deletes the refresh token, invalidating the session.
func (s *serverImpl) logoutUser(req api.Request) api.Response {
	if req.Username == "" || req.RefreshToken == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	// Delete the refresh token from 'refresh' namespace.
	if err := s.db.Delete("refresh", []byte(req.Username)); err != nil {
		return api.Response{Success: false, Message: "Error closing session"}
	}
	return api.Response{Success: true, Message: "Session closed successfully"}
}

// userExists checks if a user exists in the 'auth' namespace.
// Returns false if the user is not found.
func (s *serverImpl) userExists(username string) (bool, error) {
	_, err := s.db.Get("auth", []byte(username))
	if err != nil {
		if strings.Contains(err.Error(), "bucket no encontrado: auth") {
			return false, nil
		}
		if err.Error() == "clave no encontrada: "+username {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isAccessTokenValid verifies the access token's signature and expiration.
func (s *serverImpl) isAccessTokenValid(username, tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
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
	// Check that subject matches username.
	if claims["sub"] != username {
		return false
	}
	return true
}
