// Package client contains the user interaction logic and communication with the server.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"prac/pkg/api"
	"prac/pkg/ui"
)

// client is an internal structure that controls the session state (user, token) and logger.
type client struct {
	log         *log.Logger
	currentUser string
	authToken   string
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
			// Logged in: View data, Update data, Logout, Exit
			options = []string{
				"View data",
				"Update data",
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
				c.logoutUser()
			case 4:
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
			fmt.Println("Automatic login successful. Token saved.")
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

	// If login is successful, save currentUser and the token.
	if res.Success {
		c.currentUser = username
		c.authToken = res.Token
		fmt.Println("Login successful. Token saved.")
	}
}

// fetchData requests private data from the server.
// The server returns the data associated with the logged in user.
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

	// If successful, display the retrieved data.
	if res.Success {
		fmt.Println("Your data:", res.Data)
	}
}

// updateData requests new text and sends it to the server with ActionUpdateData.
func (c *client) updateData() {
	ui.ClearScreen()
	fmt.Println("** Update User Data **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("Not logged in. Please log in first.")
		return
	}

	// Read the new data.
	newData := ui.ReadInput("Enter the content to store")

	// Send the update request.
	res := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     newData,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)
}

// logoutUser calls the logout action on the server, and if successful,
// clears the local session (currentUser/authToken).
func (c *client) logoutUser() {
	ui.ClearScreen()
	fmt.Println("** Logout **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("Not logged in.")
		return
	}

	// Send the logout request.
	res := c.sendRequest(api.Request{
		Action:   api.ActionLogout,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

	// If successful, clear the local session.
	if res.Success {
		c.currentUser = ""
		c.authToken = ""
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
