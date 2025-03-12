package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"prac/pkg/api"
	"prac/pkg/crypto"
	"prac/pkg/ui"
)

// client is an internal structure that controls the session state (user, token)
// and holds the encryption key for end-to-end encryption.
type client struct {
	log               *log.Logger
	currentUser       string
	authToken         string // access token
	refreshToken      string // refresh token
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

// runLoop handles the main menu logic.
// Different options are shown depending on whether a user is logged in.
func (c *client) runLoop() {
	for {
		ui.ClearScreen()

		// Build a title showing the logged in user, if any.
		var title string
		if c.currentUser == "" {
			title = "Menu"
		} else {
			title = fmt.Sprintf("Menu (%s)", c.currentUser)
		}

		// Generate options dynamically based on login state.
		var options []string
		if c.currentUser == "" {
			// Not logged in: Register, Login, Exit
			options = []string{
				"Register user",
				"Login",
				"Exit",
			}
		} else {
			// Logged in: View data, Update data, Refresh token, Logout, Exit
			options = []string{
				"View data",
				"Update data",
				"Refresh token",
				"Logout",
				"Exit",
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
				// Exit option.
				c.log.Println("Exiting client...")
				return
			}
		} else {
			// Logged in.
			switch choice {
			case 1:
				c.fetchData()
			case 2:
				c.updateData()
			case 3:
				c.refreshAccessToken()
			case 4:
				c.logoutUser()
			case 5:
				// Exit option.
				c.log.Println("Exiting client...")
				return
			}
		}

		// Pause so the user can see the results.
		ui.Pause("Press [Enter] to continue...")
	}
}

// registerUser requests credentials and sends them to the server for registration.
// If registration is successful, it attempts an automatic login.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** User Registration **")

	username := ui.ReadInput("Username")
	password := ui.ReadInput("Password")

	// Send the registration request to the server.
	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: password,
	})

	// Display the result.
	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

	// If successful, attempt automatic login.
	if res.Success {
		c.log.Println("Registration successful; attempting automatic login...")

		loginRes := c.sendRequest(api.Request{
			Action:   api.ActionLogin,
			Username: username,
			Password: password,
		})
		if loginRes.Success {
			c.currentUser = username
			c.authToken = loginRes.Token
			c.refreshToken = loginRes.RefreshToken
			// Derive the encryption key using the password and username.
			key, err := crypto.DeriveKey(password, username)
			if err != nil {
				fmt.Println("Error deriving encryption key:", err)
				return
			}
			c.encryptionKey = key
			// Store the plaintext password temporarily for future key derivation.
			c.plaintextPassword = password
			fmt.Println("Automatic login successful. Tokens and encryption key saved.")
		} else {
			fmt.Println("Automatic login failed:", loginRes.Message)
		}
	}
}

// loginUser requests credentials and performs login on the server.
func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Login **")

	username := ui.ReadInput("Username")
	password := ui.ReadInput("Password")

	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: password,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

	// If login is successful, save currentUser and the tokens.
	if res.Success {
		c.currentUser = username
		c.authToken = res.Token
		c.refreshToken = res.RefreshToken
		// Derive the encryption key using the password and username.
		key, err := crypto.DeriveKey(password, username)
		if err != nil {
			fmt.Println("Error deriving encryption key:", err)
			return
		}
		c.encryptionKey = key
		// Store the plaintext password temporarily.
		c.plaintextPassword = password
		fmt.Println("Login successful. Tokens and encryption key saved.")
	}
}

// refreshAccessToken requests new tokens using the refresh token.
func (c *client) refreshAccessToken() {
	ui.ClearScreen()
	fmt.Println("** Refresh Access Token **")

	res := c.sendRequest(api.Request{
		Action:       api.ActionRefresh,
		Username:     c.currentUser,
		RefreshToken: c.refreshToken,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

	if res.Success {
		c.authToken = res.Token
		c.refreshToken = res.RefreshToken
		fmt.Println("Token refreshed successfully.")
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

	// Send the fetch data request.
	res := c.sendRequest(api.Request{
		Action:   api.ActionFetchData,
		Username: c.currentUser,
		Token:    c.authToken,
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
			decryptedData, err := crypto.Decrypt(encryptedData, c.encryptionKey)
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
	encryptedData, err := crypto.Encrypt([]byte(newData), c.encryptionKey)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}
	// Encode the encrypted data to base64 for safe JSON transmission.
	encodedData := base64.StdEncoding.EncodeToString(encryptedData)

	// Send the update request.
	res := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
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

	// Send the logout request.
	res := c.sendRequest(api.Request{
		Action:       api.ActionLogout,
		Username:     c.currentUser,
		RefreshToken: c.refreshToken,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

	// If successful, clear the local session.
	if res.Success {
		c.currentUser = ""
		c.authToken = ""
		c.refreshToken = ""
		c.encryptionKey = nil
		c.plaintextPassword = ""
	}
}

// sendRequest sends a JSON POST to the server URL and returns the decoded response.
// It is used for all actions.
func (c *client) sendRequest(req api.Request) api.Response {
	jsonData, _ := json.Marshal(req)
	// Use HTTPS for secure transport.
	resp, err := http.Post("https://localhost:8080/api", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error contacting the server:", err)
		return api.Response{Success: false, Message: "Connection error"}
	}
	defer resp.Body.Close()

	// Read the response body and unmarshal into an api.Response.
	body, _ := io.ReadAll(resp.Body)
	var res api.Response
	_ = json.Unmarshal(body, &res)
	return res
}
