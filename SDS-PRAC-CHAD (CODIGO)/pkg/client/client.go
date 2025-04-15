package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"prac/pkg/api"
	pcrypto "prac/pkg/crypto"
	"prac/pkg/functionalities"
	"prac/pkg/logging"
	"prac/pkg/ui"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

// client is an internal structure that controls the session state (user, tokens)
// and holds the encryption key for end-to-end encryption.
type client struct {
	log               *log.Logger
	currentUser       string
	currentRole       string // Nuevo campo para almacenar el rol del usuario
	authToken         string // access token
	refreshToken      string // refresh token
	accessTokenExpiry time.Time
	encryptionKey     []byte
	plaintextPassword string // temporarily store password for key derivation
}

// Run is the only exported function of this package.
// It creates an internal client and starts the main loop.
func Run() {
	// Create a logger with the prefix 'cli' to identify messages on the console.
	c := &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
	}
	c.runLoop()
}

// parseTokenExpiry extracts the expiration time from a JWT access token.
// It decodes the token payload (the second part) and returns the expiry as time.Time.
func parseTokenExpiry(tokenStr string) (time.Time, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) < 2 {
		return time.Time{}, fmt.Errorf("invalid token format")
	}
	payload := parts[1]
	// add padding if needed
	missing := len(payload) % 4
	if missing != 0 {
		payload += strings.Repeat("=", 4-missing)
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return time.Time{}, err
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return time.Time{}, err
	}
	return time.Unix(claims.Exp, 0), nil
}

// runLoop handles the main menu logic.
// It also starts a background goroutine to automatically refresh the access token.
func (c *client) runLoop() {
	// Start a background goroutine to auto-refresh the access token.
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if c.currentUser != "" && c.authToken != "" && !c.accessTokenExpiry.IsZero() {
				if time.Until(c.accessTokenExpiry) < 10*time.Second {
					c.log.Println("Auto refreshing token...")
					c.refreshAccessToken()
				}
			}
		}
	}()

	for {
		ui.ClearScreen()

		// Build a title showing the logged in user, if any.
		var title string
		if c.currentUser == "" {
			title = "Menu"
		} else {
			title = fmt.Sprintf("Menu (%s - %s)", c.currentUser, c.currentRole)
		}

		// Generate options dynamically based on login state.
		var options []string
		if c.currentUser == "" {
			// Not logged in: Register, Login, Login with public key, Exit
			options = []string{
				"Register user",
				"Login",
				"Login with public key",
				"Exit",
			}
		} else {
<<<<<<< HEAD
			// Logged in: Generate menu based on role
			switch c.currentRole {
			case "normal":
				options = []string{
					"View data",
					"Update data",
					"Vote in a poll",
					"View results",
					"Messages",
					"Logout",
					"Exit",
				}
			case "admin":
				options = []string{
					"View data",
					"Update data",
					"Vote in a poll",
					"Create a poll",
					"Modify a poll",
					"View results",
					"Create Backup",
					"Restore Backup",
					"Messages",
					"Logout",
					"Exit",
				}
			case "moderator":
				options = []string{
					"View data",
					"Update data",
					"Vote in a poll",
					"View results",
					"Ban/Unban Users",
					"Messages",
					"Logout",
					"Exit",
				}
			default:
				fmt.Println("Unknown role. Please contact support.")
				return
=======
			// Logged in: View data, Update data, Logout, Exit
			options = []string{
				"View data",
				"Update data",
				"Vote in a poll",
				"Create a poll",
				"View results",
				"Logout",
				"Exit",
				"Create Backup",
				"Restore Backup",
				"Messages",
				"View Logs",
>>>>>>> alvaro
			}
		}

		// Display the menu and get the user's choice.
		choice := ui.PrintMenu(title, options)

		// Map the chosen option based on login state.
		if c.currentUser == "" {
			// Not logged in.
			switch choice {
			case 1:
				c.registerUser()
			case 2:
				c.loginUser()
			case 3:
				c.loginWithPublicKey()
			case 4:
				// Exit option.
				c.log.Println("Exiting client...")
				return
			}

		} else {
<<<<<<< HEAD
			// Logged in: Handle actions based on role.
			switch c.currentRole {
			case "normal":
				switch choice {
				case 1:
					c.fetchData()
				case 2:
					c.updateData()
				case 3:
					c.voteInPoll()
				case 4:
					c.viewResults()
				case 5:
					c.messagesMenu()
				case 6:
					c.logoutUser()
				case 7:
					c.log.Println("Exiting client...")
					return
				}
			case "admin":
				switch choice {
				case 1:
					c.fetchData()
				case 2:
					c.updateData()
				case 3:
					c.voteInPoll()
				case 4:
					c.createPoll()
				case 5:
					//c.modifyPoll()
					return
				case 6:
					c.viewResults()
				case 7:
					c.createBackup()
				case 8:
					c.restoreBackupFromDrive()
				case 9:
					c.messagesMenu()
				case 10:
					c.logoutUser()
				case 11:
					c.log.Println("Exiting client...")
					return
				}
			case "moderator":
				switch choice {
				case 1:
					c.fetchData()
				case 2:
					c.updateData()
				case 3:
					c.voteInPoll()
				case 4:
					c.viewResults()
				case 5:
					c.banMenu()
				case 6:
					c.messagesMenu()
				case 7:
					c.logoutUser()
				case 8:
					c.log.Println("Exiting client...")
					return
				}
=======
			// Logged in.
			switch choice {
			case 1:
				c.fetchData()
			case 2:
				c.updateData()
			case 3:
				c.voteInPoll()
			case 4:
				c.createPoll()
			case 5:
				c.viewResults()
			case 6:
				c.logoutUser()
			case 7:
				// Exit option.
				c.log.Println("Exiting client...")
				return
			case 8:
				// Create a backup of the database file.
				c.createBackup()
			case 9:
				c.restoreBackupFromDrive()
			case 10:
				c.messagesMenu()
			case 11:
				// View logs
				c.viewLogs()
>>>>>>> alvaro
			}

		}

		// Pause so the user can see the results.
		ui.Pause("Press [Enter] to continue...")
	}
}

// isValidEmail validates the email format using a regex.
func isValidEmail(email string) bool {
	// simple regex for basic email validation
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// registerUser requests credentials and sends them to the server for registration.
// If registration is successful, it attempts an automatic login.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** User Registration **")

	username := ui.ReadInput("Username")
	if username == "" {
		fmt.Println("Username cannot be empty")
		return
	}
	if len(username) < 4 {
		fmt.Println("Username must have at least 4 characters")
		return
	}

	email := ui.ReadInput("Email")
	if email == "" {
		fmt.Println("Email cannot be empty")
		return
	}
	if !isValidEmail(email) {
		fmt.Println("Invalid email format")
		return
	}

	password := ui.ReadPassword("Password")
	if password == "" {
		fmt.Println("Password cannot be empty")
		return
	}
	if len(password) < 8 {
		fmt.Println("Password must have at least 8 characters")
		return
	}

	// Send the registration request to the server.
	res, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Email:    email,
		Password: password,
	})

	// Display the result.
	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

	// If successful, attempt automatic login.
	if res.Success {
		c.log.Println("Registration successful; attempting automatic login...")

		resLogin, accessToken, refreshToken := c.sendRequest(api.Request{
			Action:   api.ActionLogin,
			Email:    email,
			Password: password,
		})
		fmt.Println("Success:", resLogin.Success)
		fmt.Println("Message:", resLogin.Message)
		if resLogin.Success {
			var responseData struct {
				Username string `json:"username"`
				Role     string `json:"role"`
			}
			if err := json.Unmarshal([]byte(res.Data), &responseData); err != nil {
				fmt.Println("Error decoding response data:", err)
				return
			}

			c.currentUser = responseData.Username
			c.currentRole = responseData.Role
			// Remove "Bearer " prefix if present.
			if strings.HasPrefix(accessToken, "Bearer ") {
				accessToken = accessToken[7:]
			}
			if strings.HasPrefix(refreshToken, "Bearer ") {
				refreshToken = refreshToken[7:]
			}
			c.authToken = accessToken
			c.refreshToken = refreshToken

			context := "LECHUGA-BONIATO-AUTH-" + email

			salt := "Leviathan-" + email

			// Derive the encryption key using the password and email.
			key, err := pcrypto.DeriveKey(email, salt, context)
			if err != nil {
				fmt.Println("Error deriving encryption key:", err)
				return
			}
			c.encryptionKey = key
			// Parse and store the access token expiry.
			expiry, err := parseTokenExpiry(c.authToken)
			if err != nil {
				fmt.Println("Error parsing token expiry:", err)
			} else {
				c.accessTokenExpiry = expiry
			}
			// Store the plaintext password temporarily for future key derivation.
			c.plaintextPassword = password
			fmt.Println("Automatic login successful. Tokens and encryption key saved.")
		} else {
			fmt.Println("Automatic login failed:", resLogin.Message)
		}
	}
}

// loginUser requests credentials and performs login on the server.
func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Login **")

	email := ui.ReadInput("Email")
	if email == "" {
		fmt.Println("Email cannot be empty")
		return
	}
	if !isValidEmail(email) {
		fmt.Println("Invalid email format")
		return
	}

	password := ui.ReadPassword("Password")
	if password == "" {
		fmt.Println("Password cannot be empty")
		return
	}
	if len(password) < 8 {
		fmt.Println("Password must have at least 8 characters")
		return
	}

	res, accessToken, refreshToken := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Email:    email,
		Password: password,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

	// If login is successful, save currentUser and the tokens.
	if res.Success {
		// Expecting the decrypted username in Data
		var responseData struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}
		if err := json.Unmarshal([]byte(res.Data), &responseData); err != nil {
			fmt.Println("Error decoding response data:", err)
			return
		}

		c.currentUser = responseData.Username
		c.currentRole = responseData.Role

		if strings.HasPrefix(accessToken, "Bearer ") {
			accessToken = accessToken[7:]
		}
		if strings.HasPrefix(refreshToken, "Bearer ") {
			refreshToken = refreshToken[7:]
		}
		c.authToken = accessToken
		c.refreshToken = refreshToken

		salt := "Leviathan-" + email

		context := "LECHUGA-BONIATO-AUTH-" + email
		// Derive the encryption key using the password and email.
		key, err := pcrypto.DeriveKey(email, salt, context)
		if err != nil {
			fmt.Println("Error deriving encryption key:", err)
			return
		}
		c.encryptionKey = key
		// Parse and store the access token expiry.
		expiry, err := parseTokenExpiry(c.authToken)
		if err != nil {
			fmt.Println("Error parsing token expiry:", err)
		} else {
			c.accessTokenExpiry = expiry
		}
		// Store the plaintext password temporarily.
		c.plaintextPassword = password
		fmt.Println("Login successful. Tokens and encryption key saved.")
	}
}

func (c *client) loginWithPublicKey() {
	ui.ClearScreen()
	fmt.Println("** Public Key Login **")

	email := ui.ReadInput("Email")
	if email == "" {
		fmt.Println("Email cannot be empty")
		return
	}
	if !isValidEmail(email) {
		fmt.Println("Invalid email format")
		return
	}

	// Send the request to initiate public key login.
	res, _, _ := c.sendRequest(api.Request{
		Action: api.ActionPublicKeyLogin,
		Email:  email,
	})
	if !res.Success {
		fmt.Println("Error initiating public key login:", res.Message)
		return
	}
	// Parse the challenge and username from the response.
	var dataObj map[string]string
	if err := json.Unmarshal([]byte(res.Data), &dataObj); err != nil {
		fmt.Println("Error parsing challenge data:", err)
		return
	}
	challenge, ok1 := dataObj["challenge"]
	username, ok2 := dataObj["username"]
	role, ok3 := dataObj["role"]
	if !ok1 || !ok2 || !ok3 {
		fmt.Println("Invalid challenge data received")
		return
	}

	// Store the role temporarily
	c.currentRole = role

	// Load the auth private key from keys/users-auth/<username>/private.pem.
	authPrivKey, err := functionalities.LoadAuthPrivateKey(username)
	if err != nil {
		fmt.Println("Error loading auth private key:", err)
		return
	}

	// Sign the challenge using RSA PKCS1v15 with SHA256.
	hash := sha256.Sum256([]byte(challenge))
	signature, err := rsa.SignPKCS1v15(rand.Reader, authPrivKey, crypto.SHA256, hash[:])
	if err != nil {
		fmt.Println("Error signing challenge:", err)
		return
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Send the signature back to the server.
	resResp, accessToken, refreshToken := c.sendRequest(api.Request{
		Action: api.ActionPublicKeyLoginResponse,
		Email:  email,
		Data:   signatureB64,
	})
	fmt.Println("Success:", resResp.Success)
	fmt.Println("Message:", resResp.Message)
	if resResp.Success {
		var responseData struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}
		if err := json.Unmarshal([]byte(res.Data), &responseData); err != nil {
			fmt.Println("Error decoding response data:", err)
			return
		}

		c.currentUser = responseData.Username
		c.currentRole = responseData.Role

		if strings.HasPrefix(accessToken, "Bearer ") {
			accessToken = accessToken[7:]
		}
		if strings.HasPrefix(refreshToken, "Bearer ") {
			refreshToken = refreshToken[7:]
		}
		c.authToken = accessToken
		c.refreshToken = refreshToken

		// Derive the encryption key solely from the email.
		salt := "Leviathan-" + email
		context := "LECHUGA-BONIATO-AUTH-" + email
		key, err := pcrypto.DeriveKey(email, salt, context)
		if err != nil {
			fmt.Println("Error deriving encryption key:", err)
			return
		}
		c.encryptionKey = key

		expiry, err := parseTokenExpiry(c.authToken)
		if err != nil {
			fmt.Println("Error parsing token expiry:", err)
		} else {
			c.accessTokenExpiry = expiry
		}
		fmt.Println("Public key login successful. Tokens saved.")
	} else {
		return
	}
}

// refreshAccessToken automatically requests new tokens using the refresh token.
func (c *client) refreshAccessToken() {
	// Do not proceed if there is no valid refresh token.
	if c.currentUser == "" || c.refreshToken == "" {
		return
	}
	res, accessToken, refreshToken := c.sendRequest(api.Request{
		Action:   api.ActionRefresh,
		Username: c.currentUser,
	})
	fmt.Println("Auto refresh - Success:", res.Success)
	fmt.Println("Auto refresh - Message:", res.Message)

	if res.Success {
		if strings.HasPrefix(accessToken, "Bearer ") {
			accessToken = accessToken[7:]
		}
		if strings.HasPrefix(refreshToken, "Bearer ") {
			refreshToken = refreshToken[7:]
		}
		c.authToken = accessToken
		c.refreshToken = refreshToken
		// Update the access token expiry.
		expiry, err := parseTokenExpiry(c.authToken)
		if err != nil {
			fmt.Println("Error parsing token expiry:", err)
		} else {
			c.accessTokenExpiry = expiry
		}
		fmt.Println("Token refreshed automatically.")
	}
}

// fetchData requests private data from the server.
// The server returns the encrypted data associated with the logged in user.
func (c *client) fetchData() {
	ui.ClearScreen()
	fmt.Println("** Get User Data **")

	// Basic check for a valid session.
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("Not logged in. Please log in first.")
		return
	}

	res, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionFetchData,
		Username: c.currentUser,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

	// If successful, decrypt and display the retrieved data.
	if res.Success {
		if res.Data != "" {
			// Decode the base64 encoded encrypted data.
			encryptedData, err := base64.StdEncoding.DecodeString(res.Data)
			if err != nil {
				fmt.Println("Error decoding data:", err)
				return
			}
			// Decrypt the data using the encryption key.
			decryptedData, err := pcrypto.Decrypt(encryptedData, c.encryptionKey)
			if err != nil {
				fmt.Println("Error decrypting data:", err)
				return
			}
			fmt.Println("Your data:", string(decryptedData))
		} else {
			fmt.Println("No data found.")
		}
	}
}

// updateData requests new text and sends it to the server with ActionUpdateData.
// The data is encrypted on the client side before sending.
func (c *client) updateData() {
	ui.ClearScreen()
	fmt.Println("** Update User Data **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("Not logged in. Please log in first.")
		return
	}

	// Read the new data.
	newData := ui.ReadInput("Enter the content to store")

	// Encrypt the data using the encryption key.
	encryptedData, err := pcrypto.Encrypt([]byte(newData), c.encryptionKey)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}
	// Encode the encrypted data to base64 for safe JSON transmission.
	encodedData := base64.StdEncoding.EncodeToString(encryptedData)

	res, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Data:     encodedData,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)
}

// logoutUser calls the logout action on the server, and if successful,
// clears the local session (currentUser, tokens, encryptionKey).
func (c *client) logoutUser() {
	ui.ClearScreen()
	fmt.Println("** Logout **")

	if c.currentUser == "" || c.refreshToken == "" {
		fmt.Println("Not logged in.")
		return
	}

	res, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionLogout,
		Username: c.currentUser,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

	// If successful, clear the local session.
	if res.Success {
		c.currentUser = ""
		c.authToken = ""
		c.refreshToken = ""
		c.accessTokenExpiry = time.Time{}
		c.encryptionKey = nil
		c.plaintextPassword = ""
	}
}

// sendRequest sends a JSON POST to the server URL and returns the decoded response,
// along with the access and refresh tokens extracted from the response headers.
// It is used for all actions.
func (c *client) sendRequest(req api.Request) (api.Response, string, string) {
	jsonData, _ := json.Marshal(req)
	request, err := http.NewRequest("POST", "https://localhost:9200/api", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return api.Response{Success: false, Message: "Request error"}, "", ""
	}
	request.Header.Set("Content-Type", "application/json")
	switch req.Action {
	case api.ActionFetchData, api.ActionUpdateData:
		if c.authToken != "" {
			request.Header.Set("Authorization", "Bearer "+c.authToken)
		}
	case api.ActionRefresh, api.ActionLogout:
		if c.refreshToken != "" {
			request.Header.Set("X-Refresh-Token", "Bearer "+c.refreshToken)
		}
	}

	// Create HTTP client with TLS verification disabled
	clientHttp := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	//clientHttp := &http.Client{}

	resp, err := clientHttp.Do(request)
	if err != nil {
		fmt.Println("Error contacting server:", err)
		return api.Response{Success: false, Message: "Connection error"}, "", ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var res api.Response
	_ = json.Unmarshal(body, &res)

	accessToken := resp.Header.Get("Authorization")
	refreshToken := resp.Header.Get("X-Refresh-Token")
	return res, accessToken, refreshToken
}

// Create Backup
func (c *client) createBackup() {
	ui.ClearScreen()
	fmt.Println("** Create Backup **")

	res, _, _ := c.sendRequest(api.Request{
		Action: api.ActionBackup,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)
}

// listBackupsFromGoogleDrive lists all backup files in the specified Google Drive folder.
func listBackupsFromGoogleDrive(folderID string, credentialsPath string) (map[string]string, error) {
	ctx := context.Background()

	// Authenticate using the credentials JSON file.
	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return nil, fmt.Errorf("error creating Google Drive service: %v", err)
	}

	// Query files in the folder.
	query := fmt.Sprintf("'%s' in parents and trashed = false", folderID)
	// filepath: /pkg/client/client.go
	fileList, err := srv.Files.List().Q(query).Fields("files(id, name)").Do()
	if err != nil {
		return nil, fmt.Errorf("error listing files in Google Drive: %v", err)
	}

	// Cambiar el acceso a los archivos
	files := make(map[string]string)
	for _, file := range fileList.Files {
		files[file.Name] = file.Id
	}

	return files, nil
}

// restoreBackupFromDrive allows the user to select and restore a backup from Google Drive.
func (c *client) restoreBackupFromDrive() {
	ui.ClearScreen()
	fmt.Println("** Restore Backup from Google Drive **")

	credentialsPath := "keys/credentials.json"           // Ruta al archivo JSON con las credenciales.
	driveFolderID := "11gN_pH9h0RJkyQ19mZEtJLxVbEyH6ZFt" // ID de la carpeta de Google Drive.

	// Listar los backups disponibles.
	files, err := listBackupsFromGoogleDrive(driveFolderID, credentialsPath)
	if err != nil {
		fmt.Println("Error listing backups:", err)
		return
	}

	if len(files) == 0 {
		fmt.Println("No backups available in Google Drive.")
		return
	}

	fmt.Println("Available backups:")
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	for i, name := range names {
		fmt.Printf("%d. %s\n", i+1, name)
	}
	fmt.Println("Enter the number of the backup to restore, or 'q' to return to the main menu.")

	// Solicitar la elección del usuario.
	for {
		input := ui.ReadInput("Select a backup to restore (or 'q' to quit)")
		if strings.ToLower(input) == "q" {
			fmt.Println("Returning to the main menu...")
			return
		}

		choice, err := strconv.Atoi(input)
		if err != nil || choice < 1 || choice > len(names) {
			fmt.Println("Invalid choice. Please enter a valid number or 'q' to quit.")
			continue
		}

		selectedName := names[choice-1]
		selectedID := files[selectedName]

		// Enviar la solicitud para restaurar el backup.
		res, _, _ := c.sendRequest(api.Request{
			Action: api.ActionRestore,
			Data:   selectedID,
		})

		// Mostrar el resultado.
		fmt.Println("Success:", res.Success)
		fmt.Println("Message:", res.Message)
		return
	}
}
func (c *client) messagesMenu() {
	ui.ClearScreen()
	fmt.Println("---------------------------------")
	fmt.Println("      CHAT WITH OTHER USERS")
	fmt.Println("---------------------------------")

	// Request the list of usernames from the server.
	res, _, _ := c.sendRequest(api.Request{
		Action: api.ActionGetUsernames,
	})
	if !res.Success {
		fmt.Println("Error fetching usernames:", res.Message)
		return
	}

	var usernames []string
	if err := json.Unmarshal([]byte(res.Data), &usernames); err != nil {
		fmt.Println("Error decoding usernames:", err)
		return
	}

	// Filter out the current user.
	var availableUsers []string
	for _, user := range usernames {
		if user != c.currentUser {
			availableUsers = append(availableUsers, user)
		}
	}
	if len(availableUsers) == 0 {
		fmt.Println("No users available.")
		return
	}

	fmt.Println("Available Users:")
	for i, name := range availableUsers {
		fmt.Printf("%d. %s\n", i+1, name)
	}
	choice := ui.ReadInt("Select the number of the user you want to chat with")
	if choice < 1 || choice > len(availableUsers) {
		fmt.Println("Invalid choice.")
		return
	}
	recipient := availableUsers[choice-1]
	ui.ClearScreen()
	fmt.Println("---------------------------------")
	fmt.Printf("  Conversation with %s\n", recipient)
	fmt.Println("---------------------------------")

	// Start conversation view.
	c.conversationView(recipient)
}

// conversationView handles a chat conversation with the specified recipient.
func (c *client) conversationView(recipient string) {
	for {
		// Retrieve chat history from the server.
		res, _, _ := c.sendRequest(api.Request{
			Action:   api.ActionGetMessages,
			Username: recipient,
			Sender:   c.currentUser,
		})
		if res.Success {
			var chatMessages []struct {
				Sender string `json:"sender"`
				Packet string `json:"packet"`
			}
			if err := json.Unmarshal([]byte(res.Data), &chatMessages); err != nil {
				fmt.Println("Error decoding chat messages:", err)
			} else {
				for _, msg := range chatMessages {
					var senderPub *rsa.PublicKey
					if msg.Sender == c.currentUser {
						pub, err := functionalities.LoadPublicKey(c.currentUser)
						if err != nil {
							fmt.Printf("You: [Error loading your public key]\n")
							continue
						}
						senderPub = pub
					} else {
						pub, err := functionalities.LoadPublicKey(recipient)
						if err != nil {
							fmt.Printf("%s: [Error loading %s's public key]\n", msg.Sender, recipient)
							continue
						}
						senderPub = pub
					}

					var packet functionalities.EncryptedPacket
					unquotedPacket, err := strconv.Unquote(msg.Packet)
					if err != nil {
						unquotedPacket = msg.Packet
					}
					if err := json.Unmarshal([]byte(unquotedPacket), &packet); err != nil {
						fmt.Printf("%s: [Error decoding packet]\n", msg.Sender)
						continue
					}
					priv, err := functionalities.LoadPrivateKey(c.currentUser)
					if err != nil {
						fmt.Printf("%s: [Error loading your private key]\n", msg.Sender)
						continue
					}
					isSender := msg.Sender == c.currentUser
					decrypted, err := functionalities.DecryptEncryptedPacket(&packet, priv, senderPub, isSender)
					if err != nil {
						fmt.Printf("%s: [Error decrypting message]\n", msg.Sender)
						continue
					}
					displayName := msg.Sender
					if msg.Sender == c.currentUser {
						displayName = "You"
					}
					fmt.Printf("%s: %s\n", displayName, string(decrypted))
				}
			}
		} else {
			fmt.Println("Error retrieving chat history:", res.Message)
		}

		fmt.Println("---------------------------------")
		newMsg := ui.ReadInput("Type your message (or type EXIT to go back)")
		if strings.ToUpper(newMsg) == "EXIT" {
			break
		}
		// Prevent sending empty messages.
		if strings.TrimSpace(newMsg) == "" {
			fmt.Println("Cannot send an empty message")
			continue
		}
		recipientPub, err := functionalities.LoadPublicKey(recipient)
		if err != nil {
			fmt.Println("Error loading recipient public key:", err)
			continue
		}
		senderPriv, err := functionalities.LoadPrivateKey(c.currentUser)
		if err != nil {
			fmt.Println("Error loading your private key:", err)
			continue
		}
		packet, err := functionalities.CreateEncryptedPacket([]byte(newMsg), recipientPub, senderPriv)
		if err != nil {
			fmt.Println("Error creating encrypted packet:", err)
			continue
		}
		packetJSON, err := json.Marshal(packet)
		if err != nil {
			fmt.Println("Error encoding packet:", err)
			continue
		}
		sendRes, _, _ := c.sendRequest(api.Request{
			Action:   api.ActionSendMessage,
			Username: recipient,
			Sender:   c.currentUser,
			Data:     string(packetJSON),
		})
		if !sendRes.Success {
			fmt.Println("Error sending message:", sendRes.Message)
		}
	}
}

<<<<<<< HEAD
// banMenu allows moderators to ban or unban users.
func (c *client) banMenu() {
	ui.ClearScreen()
	fmt.Println("** Ban/Unban Users **")

	options := []string{"Ban a user", "Unban a user", "Back"}
	choice := ui.PrintMenu("Ban/Unban Menu", options)

	switch choice {
	case 1: // Ban a user
		username := c.selectUser("Select a user to ban")
		if username == "" {
			fmt.Println("No user selected.")
			return
		}

		// Check if the user is already banned
		statusRes, _, _ := c.sendRequest(api.Request{
			Action:   api.ActionCheckBanStatus,
			Username: username,
		})
		if statusRes.Message == "User is banned" {
			fmt.Printf("The user '%s' is already banned.\n", username)
			return
		}

		// Proceed to ban the user
		res, _, _ := c.sendRequest(api.Request{
			Action:   api.ActionBanUser,
			Username: username,
		})
		fmt.Println("Success:", res.Success)
		fmt.Println("Message:", res.Message)

	case 2: // Unban a user
		username := c.selectUser("Select a user to unban")
		if username == "" {
			fmt.Println("No user selected.")
			return
		}

		// Check if the user is not banned
		statusRes, _, _ := c.sendRequest(api.Request{
			Action:   api.ActionCheckBanStatus,
			Username: username,
		})
		if statusRes.Message == "User is not banned" {
			fmt.Printf("The user '%s' is not banned.\n", username)
			return
		}

		// Proceed to unban the user
		res, _, _ := c.sendRequest(api.Request{
			Action:   api.ActionUnbanUser,
			Username: username,
		})
		fmt.Println("Success:", res.Success)
		fmt.Println("Message:", res.Message)

	case 3: // Back
		return
	}
}

// Helper function to fetch and display a list of users for selection.
func (c *client) selectUser(prompt string) string {
	// Request the list of usernames from the server.
	res, _, _ := c.sendRequest(api.Request{
		Action: api.ActionGetUsernames,
	})
	if !res.Success {
		fmt.Println("Error fetching usernames:", res.Message)
		return ""
	}

	var usernames []string
	if err := json.Unmarshal([]byte(res.Data), &usernames); err != nil {
		fmt.Println("Error decoding usernames:", err)
		return ""
	}

	if len(usernames) == 0 {
		fmt.Println("No users available.")
		return ""
	}

	// Display the list of users.
	fmt.Println(prompt)
	for i, name := range usernames {
		fmt.Printf("%d. %s\n", i+1, name)
	}

	// Let the user select a user.
	choice := ui.ReadInt("Select a user")
	if choice < 1 || choice > len(usernames) {
		fmt.Println("Invalid choice.")
		return ""
	}

	return usernames[choice-1]
}
=======
func (c *client) viewLogs() {
	ui.ClearScreen()
	fmt.Println("** Ver Logs **")

	credentialsPath := "keys/credentials.json"           // Ruta al archivo JSON con las credenciales.
	driveFolderID := "1ka0Ec2EnHcF2qrvk9nsaSpI124jkLMwj" // ID de la carpeta de Google Drive.

	// Listar los logs disponibles en Google Drive.
	files, err := listBackupsFromGoogleDrive(driveFolderID, credentialsPath)

	// Filtrar solo los archivos con extensión .enc
	filteredFiles := make(map[string]string)
	for name, id := range files {
		if strings.HasSuffix(name, ".enc") {
			filteredFiles[name] = id
		}
	}
	files = filteredFiles

	if err != nil {
		fmt.Println("Error al listar los logs:", err)
		return
	}

	if len(files) == 0 {
		fmt.Println("No hay logs disponibles en Google Drive.")
		return
	}

	fmt.Println("Logs disponibles:")
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	for i, name := range names {
		fmt.Printf("%d. %s\n", i+1, name)
	}
	fmt.Println("Selecciona un log para ver su contenido o presiona 'q' para volver al menú principal.")

	// Solicitar la elección del usuario.
	for {
		input := ui.ReadInput("Selecciona un log (o 'q' para salir)")
		if strings.ToLower(input) == "q" {
			fmt.Println("Volviendo al menú principal...")
			return
		}

		choice, err := strconv.Atoi(input)
		if err != nil || choice < 1 || choice > len(names) {
			fmt.Println("Elección inválida. Por favor, selecciona un número válido o 'q' para salir.")
			continue
		}

		selectedName := names[choice-1]
		selectedID := files[selectedName]

		// Descargar el log desde Google Drive.
		tempFilePath := filepath.Join(os.TempDir(), selectedName)
		if err := logging.DownloadLogFromGoogleDrive(selectedID, tempFilePath, credentialsPath); err != nil {
			fmt.Println("Error al descargar el log:", err)
			return
		}

		// Desencriptar el log.
		decryptedFilePath := tempFilePath + ".dec"
		if err := logging.DecryptFile(tempFilePath, decryptedFilePath, "keys/logs_encryption.key"); err != nil {
			fmt.Println("Error al desencriptar el log:", err)
			return
		}

		// Mostrar el contenido del log.
		content, err := os.ReadFile(decryptedFilePath)
		if err != nil {
			fmt.Println("Error al leer el log desencriptado:", err)
			return
		}

		fmt.Println("\nContenido del log:")
		fmt.Println(string(content))
		fmt.Println("\nPresiona 'q' para volver al menú principal.")
		ui.ReadInput("")

		// Limpiar archivos temporales.
		os.Remove(tempFilePath)
		os.Remove(decryptedFilePath)
		return
	}
}
>>>>>>> alvaro
