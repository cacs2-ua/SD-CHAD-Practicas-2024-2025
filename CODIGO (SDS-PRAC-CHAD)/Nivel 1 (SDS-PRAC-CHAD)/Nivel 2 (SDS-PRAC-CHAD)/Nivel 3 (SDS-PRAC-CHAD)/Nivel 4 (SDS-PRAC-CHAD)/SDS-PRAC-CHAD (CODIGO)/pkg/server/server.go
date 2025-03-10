// Package server contains the server code.
// It interacts with the client via a JSON/HTTP API.
package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"prac/pkg/api"
	"prac/pkg/store"

	"golang.org/x/crypto/bcrypt"
)

// server encapsulates the state of our server.
type server struct {
	db  store.Store // database
	log *log.Logger // logger for error and info messages
}

// generateSecureToken creates a secure random token of 16 bytes and returns it as a hex string.
func generateSecureToken() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Run starts the database and the HTTPS server.
func Run() error {
	// Open the database using the bbolt engine.
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error opening database: %v", err)
	}

	// Create our server with a logger with prefix "srv".
	srv := &server{
		db:  db,
		log: log.New(os.Stdout, "[srv] ", log.LstdFlags),
	}

	// Ensure the database is closed when the function ends.
	defer srv.db.Close()

	// Create a new ServeMux and associate /api with our apiHandler.
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Start the HTTPS server on port 8080 using TLS.
	// Make sure to place server.crt and server.key inside a "certs" folder at the project root.
	err = http.ListenAndServeTLS(":8080", "certs/server.crt", "certs/server.key", mux)
	return err
}

// apiHandler decodes the JSON request, dispatches it to the corresponding function,
// and returns the JSON response.
func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
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
// It hashes the password using bcrypt, stores it in the "auth" namespace,
// creates an empty entry in "userdata" for the user, and stores the public key
// in the "pubkeys" namespace.
func (s *server) registerUser(req api.Request) api.Response {
	// Basic validation.
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}

	// Check if the user already exists in "auth".
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

	// Store the hashed password in the "auth" namespace (key=username, value=hashed password).
	if err := s.db.Put("auth", []byte(req.Username), hashedPassword); err != nil {
		return api.Response{Success: false, Message: "Error saving credentials"}
	}

	// Create an empty entry for user data in "userdata".
	if err := s.db.Put("userdata", []byte(req.Username), []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error initializing user data"}
	}

	// If a public key is provided, store it in the "pubkeys" namespace.
	if req.PublicKey != "" {
		if err := s.db.Put("pubkeys", []byte(req.Username), []byte(req.PublicKey)); err != nil {
			return api.Response{Success: false, Message: "Error saving public key"}
		}
	}

	return api.Response{Success: true, Message: "User registered"}
}

// loginUser validates credentials in the "auth" namespace and generates a secure token in "sessions".
func (s *server) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}

	// Retrieve the stored hashed password from "auth".
	storedHash, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}

	// Compare the stored hash with the password provided.
	if err := bcrypt.CompareHashAndPassword(storedHash, []byte(req.Password)); err != nil {
		return api.Response{Success: false, Message: "Invalid credentials"}
	}

	// Generate a secure random token.
	token, err := generateSecureToken()
	if err != nil {
		return api.Response{Success: false, Message: "Error generating token"}
	}

	// Store the token in the "sessions" namespace.
	if err := s.db.Put("sessions", []byte(req.Username), []byte(token)); err != nil {
		return api.Response{Success: false, Message: "Error creating session"}
	}

	return api.Response{Success: true, Message: "Login successful", Token: token}
}

// fetchData verifies the token and returns the content from the "userdata" namespace.
func (s *server) fetchData(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired token"}
	}

	// Retrieve the data associated with the user from "userdata".
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

// updateData updates the content of "userdata" after verifying the token.
func (s *server) updateData(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired token"}
	}

	// Store the new data.
	if err := s.db.Put("userdata", []byte(req.Username), []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error updating user data"}
	}

	return api.Response{Success: true, Message: "User data updated"}
}

// logoutUser deletes the session in "sessions", invalidating the token.
func (s *server) logoutUser(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired token"}
	}

	// Delete the session entry in "sessions".
	if err := s.db.Delete("sessions", []byte(req.Username)); err != nil {
		return api.Response{Success: false, Message: "Error closing session"}
	}

	return api.Response{Success: true, Message: "Session closed successfully"}
}

// userExists checks if a user exists in the "auth" namespace.
// Returns false if the user is not found.
func (s *server) userExists(username string) (bool, error) {
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

// isTokenValid checks if the token stored in "sessions" matches the provided token.
func (s *server) isTokenValid(username, token string) bool {
	storedToken, err := s.db.Get("sessions", []byte(username))
	if err != nil {
		return false
	}
	return string(storedToken) == token
}
