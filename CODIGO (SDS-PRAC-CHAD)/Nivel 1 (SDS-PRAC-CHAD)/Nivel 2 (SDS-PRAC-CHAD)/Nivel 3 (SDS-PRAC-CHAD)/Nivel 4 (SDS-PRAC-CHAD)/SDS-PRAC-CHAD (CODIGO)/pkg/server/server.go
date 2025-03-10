// Package server contains the server code.
// It interacts with the client via a JSON/HTTP API.
package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"prac/pkg/api"
	"prac/pkg/store"
)

// server encapsulates the state of our server.
type server struct {
	db           store.Store // database
	log          *log.Logger // logger for error and info messages
	tokenCounter int64       // counter to generate tokens
}

// Run starts the database and the HTTPS server.
func Run() error {
	// Open the database using the bbolt engine.
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error opening database: %v", err)
	}

	// Create our server with a logger with prefix 'srv'.
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

// generateToken creates a unique token by incrementing an internal counter (not very secure).
func (s *server) generateToken() string {
	id := atomic.AddInt64(&s.tokenCounter, 1)
	return fmt.Sprintf("token_%d", id)
}

// registerUser registers a new user if they do not exist.
// It stores the password in the 'auth' namespace and creates an empty entry in 'userdata' for the user.
func (s *server) registerUser(req api.Request) api.Response {
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

	// Store the password in the 'auth' namespace (key=username, value=password).
	if err := s.db.Put("auth", []byte(req.Username), []byte(req.Password)); err != nil {
		return api.Response{Success: false, Message: "Error saving credentials"}
	}

	// Create an empty entry for user data in 'userdata'.
	if err := s.db.Put("userdata", []byte(req.Username), []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error initializing user data"}
	}

	return api.Response{Success: true, Message: "User registered"}
}

// loginUser validates credentials in the 'auth' namespace and generates a token in 'sessions'.
func (s *server) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}

	// Retrieve the stored password from 'auth'.
	storedPass, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "User not found"}
	}

	// Compare passwords.
	if string(storedPass) != req.Password {
		return api.Response{Success: false, Message: "Invalid credentials"}
	}

	// Generate a new token and store it in 'sessions'.
	token := s.generateToken()
	if err := s.db.Put("sessions", []byte(req.Username), []byte(token)); err != nil {
		return api.Response{Success: false, Message: "Error creating session"}
	}

	return api.Response{Success: true, Message: "Login successful", Token: token}
}

// fetchData verifies the token and returns the content from the 'userdata' namespace.
func (s *server) fetchData(req api.Request) api.Response {
	// Check credentials.
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired token"}
	}

	// Retrieve the data associated with the user from 'userdata'.
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

// updateData updates the content of 'userdata' (the user's data) after verifying the token.
func (s *server) updateData(req api.Request) api.Response {
	// Check credentials.
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired token"}
	}

	// Update the user data in 'userdata'.
	if err := s.db.Put("userdata", []byte(req.Username), []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error updating user data"}
	}

	return api.Response{Success: true, Message: "User data updated"}
}

// logoutUser deletes the session in 'sessions', invalidating the token.
func (s *server) logoutUser(req api.Request) api.Response {
	// Check credentials.
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Missing credentials"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Invalid or expired token"}
	}

	// Delete the session entry in 'sessions'.
	if err := s.db.Delete("sessions", []byte(req.Username)); err != nil {
		return api.Response{Success: false, Message: "Error closing session"}
	}

	return api.Response{Success: true, Message: "Session closed successfully"}
}

// userExists checks if a user exists in the 'auth' namespace.
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

// isTokenValid checks if the token stored in 'sessions' matches the provided token.
func (s *server) isTokenValid(username, token string) bool {
	storedToken, err := s.db.Get("sessions", []byte(username))
	if err != nil {
		return false
	}
	return string(storedToken) == token
}
