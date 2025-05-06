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

type client struct {
	log               *log.Logger
	currentUser       string
	currentRole       string
	currentGroup      string
	authToken         string
	refreshToken      string
	accessTokenExpiry time.Time
	encryptionKey     []byte
	plaintextPassword string
}

func Run() {
	c := &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
	}
	c.runLoop()
}

func parseTokenExpiry(tokenStr string) (time.Time, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) < 2 {
		return time.Time{}, fmt.Errorf("invalid token format")
	}
	payload := parts[1]
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

func (c *client) runLoop() {
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

		var title string
		if c.currentUser == "" {
			title = "Menu"
		} else {
			title = fmt.Sprintf(
				"Menu (username: \"%s\" - role: \"%s\" - user_group: \"%s\")",
				c.currentUser,
				c.currentRole,
				c.currentGroup,
			)
		}

		var options []string
		if c.currentUser == "" {
			options = []string{
				"Register user",
				"Login",
				"Login with public key",
				"Exit",
			}
		} else {
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
					"Modify user role",
					"Vote in a poll",
					"Create a poll",
					"Modify a poll",
					"View results",
					"Create Backup",
					"Restore Backup",
					"Messages",
					"View Logs",
					"Create user groups",
					"Modify user groups",
					"Delete user groups",
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
					"View Logs",
					"Create user groups",
					"Modify user groups",
					"Delete user groups",
					"Logout",
					"Exit",
				}
			default:
				fmt.Println("Unknown role. Please contact support.")
				return
			}
		}

		choice := ui.PrintMenu(title, options)

		if c.currentUser == "" {
			switch choice {
			case 1:
				c.registerUser()
			case 2:
				c.loginUser()
			case 3:
				c.loginWithPublicKey()
			case 4:
				c.log.Println("Exiting client...")
				return
			}

		} else {
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
					c.createUserGroup()
				case 7:
					c.debugUserGroups()
				case 8:
					c.logoutUser()
				case 9:
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
					c.modifyUserRole()
				case 4:
					c.voteInPoll()
				case 5:
					c.createPoll()
				case 6:
					c.modifyPoll()
				case 7:
					c.viewResults()
				case 8:
					c.createBackup()
				case 9:
					c.restoreBackupFromDrive()
				case 10:
					c.messagesMenu()
				case 11:
					c.viewLogs()
				case 12:
					c.createUserGroup()
				case 13:
					c.editUserGroup()
				case 14:
					c.deleteUserGroup()
				case 15:
					c.debugUserGroups()
				case 16:
					c.listUserGroups()
				case 17:
					c.logoutUser()
				case 18:
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
					c.viewLogs()
				case 8:
					c.createUserGroup()
				case 9:
					c.editUserGroup()
				case 10:
					c.deleteUserGroup()
				case 11:
					c.logoutUser()
				case 12:
					c.log.Println("Exiting client...")
					return
				}
			}

		}

		ui.Pause("Press [Enter] to continue...")
	}
}

func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** User Registration **")

	rawUsername := ui.ReadInput("Username")
	username := strings.TrimSpace(rawUsername)
	if username == "" {
		fmt.Println("Username cannot be empty")
		return
	}

	rawUserGroup := ui.ReadInput("User group")
	userGroup := strings.TrimSpace(rawUserGroup)
	if userGroup == "" {
		fmt.Println("User group cannot be empty")
		return
	}

	if len(userGroup) < 4 {
		fmt.Println("User group must have at least 4 characters")
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

	rawPassword := ui.ReadPassword("Password")
	password := strings.TrimSpace(rawPassword)
	if password == "" {
		fmt.Println("Password cannot be empty")
		return
	}
	if len(password) < 8 {
		fmt.Println("Password must have at least 8 characters")
		return
	}

	res, _, _ := c.sendRequest(api.Request{
		Action:    api.ActionRegister,
		Username:  username,
		Email:     email,
		Password:  password,
		UserGroup: userGroup,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

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
				Username  string `json:"username"`
				Role      string `json:"role"`
				UserGroup string `json:"user_group"`
			}
			if err := json.Unmarshal([]byte(resLogin.Data), &responseData); err != nil {
				fmt.Println("Error decoding login response data:", err)
				return
			}

			c.currentUser = responseData.Username
			c.currentRole = responseData.Role
			c.currentGroup = responseData.UserGroup
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
			c.plaintextPassword = password
			fmt.Println("Automatic login successful. Tokens and encryption key saved.")
		} else {
			fmt.Println("Automatic login failed:", resLogin.Message)
		}
	}
}

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

	if res.Success {
		var responseData struct {
			Username  string `json:"username"`
			Role      string `json:"role"`
			UserGroup string `json:"user_group"`
		}
		if err := json.Unmarshal([]byte(res.Data), &responseData); err != nil {
			fmt.Println("Error decoding response data:", err)
			return
		}

		c.currentUser = responseData.Username
		c.currentRole = responseData.Role
		c.currentGroup = responseData.UserGroup

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

	res, _, _ := c.sendRequest(api.Request{
		Action: api.ActionPublicKeyLogin,
		Email:  email,
	})
	if !res.Success {
		fmt.Println("Error initiating public key login:", res.Message)
		return
	}
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

	c.currentRole = role

	authPrivKey, err := functionalities.LoadAuthPrivateKey(username)
	if err != nil {
		fmt.Println("Error loading auth private key:", err)
		return
	}

	hash := sha256.Sum256([]byte(challenge))
	signature, err := rsa.SignPKCS1v15(rand.Reader, authPrivKey, crypto.SHA256, hash[:])
	if err != nil {
		fmt.Println("Error signing challenge:", err)
		return
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	resResp, accessToken, refreshToken := c.sendRequest(api.Request{
		Action: api.ActionPublicKeyLoginResponse,
		Email:  email,
		Data:   signatureB64,
	})
	fmt.Println("Success:", resResp.Success)
	fmt.Println("Message:", resResp.Message)
	if resResp.Success {
		var responseData struct {
			Username  string `json:"username"`
			Role      string `json:"role"`
			UserGroup string `json:"user_group"`
		}
		if err := json.Unmarshal([]byte(resResp.Data), &responseData); err != nil {
			fmt.Println("Error decoding response data:", err)
			return
		}

		c.currentUser = username
		c.currentRole = responseData.Role
		c.currentGroup = responseData.UserGroup

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
		expiry, err := parseTokenExpiry(c.authToken)
		if err != nil {
			fmt.Println("Error parsing token expiry:", err)
		} else {
			c.accessTokenExpiry = expiry
		}
		fmt.Println("Token refreshed automatically.")
	}
}

func (c *client) fetchData() {
	ui.ClearScreen()
	fmt.Println("** Get User Data **")

<<<<<<< HEAD
	// Verificar si el usuario está autenticado
=======
>>>>>>> develop
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("Not logged in. Please log in first.")
		return
	}

	// Obtener los datos privados del usuario
	res, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionFetchData,
		Username: c.currentUser,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

<<<<<<< HEAD
	// Si la solicitud fue exitosa, desencriptar y mostrar los datos
=======
>>>>>>> develop
	if res.Success {
		if res.Data != "" {
			encryptedData, err := base64.StdEncoding.DecodeString(res.Data)
			if err != nil {
				fmt.Println("Error decoding data:", err)
				return
			}
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

	// Obtener los grupos de usuario
	groupRes, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionListUserGroupsForUser,
		Username: c.currentUser,
	})

	if !groupRes.Success {
		fmt.Println("Error fetching user groups:", groupRes.Message)
		return
	}

	var userGroups []string
	if err := json.Unmarshal([]byte(groupRes.Data), &userGroups); err != nil {
		fmt.Println("Error decoding user groups:", err)
		return
	}

	// Mostrar los grupos de usuario
	fmt.Println("\nYour User Groups:")
	if len(userGroups) == 0 {
		fmt.Println("You have no groups.")
	} else {
		for _, group := range userGroups {
			fmt.Printf("- %s\n", group)
		}
	}
}

func (c *client) updateData() {
	ui.ClearScreen()
	fmt.Println("** Update User Data **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("Not logged in. Please log in first.")
		return
	}

	newData := ui.ReadInput("Enter the content to store")

	encryptedData, err := pcrypto.Encrypt([]byte(newData), c.encryptionKey)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}
	encodedData := base64.StdEncoding.EncodeToString(encryptedData)

	res, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Data:     encodedData,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)
}

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

	if res.Success {
		c.currentUser = ""
		c.authToken = ""
		c.refreshToken = ""
		c.accessTokenExpiry = time.Time{}
		c.encryptionKey = nil
		c.plaintextPassword = ""
	}
}

func (c *client) sendRequest(req api.Request) (api.Response, string, string) {
	jsonData, _ := json.Marshal(req)
	request, err := http.NewRequest("POST", "https://localhost:9200/api", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return api.Response{Success: false, Message: "Request error"}, "", ""
	}
	request.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		switch req.Action {
		case api.ActionRegister,
			api.ActionLogin,
			api.ActionPublicKeyLogin,
			api.ActionPublicKeyLoginResponse:
		default:
			request.Header.Set("Authorization", "Bearer "+c.authToken)
		}
	}

	if c.refreshToken != "" {
		switch req.Action {
		case api.ActionRefresh, api.ActionLogout:
			request.Header.Set("X-Refresh-Token", "Bearer "+c.refreshToken)
		}
	}

	clientHttp := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

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

func (c *client) createBackup() {
	ui.ClearScreen()
	fmt.Println("** Create Backup **")

	res, _, _ := c.sendRequest(api.Request{
		Action: api.ActionBackup,
	})

	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)
}

func listBackupsFromGoogleDrive(folderID string, credentialsPath string) (map[string]string, error) {
	ctx := context.Background()

	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return nil, fmt.Errorf("error creating Google Drive service: %v", err)
	}

	query := fmt.Sprintf("'%s' in parents and trashed = false", folderID)
	fileList, err := srv.Files.List().Q(query).Fields("files(id, name)").Do()
	if err != nil {
		return nil, fmt.Errorf("error listing files in Google Drive: %v", err)
	}

	files := make(map[string]string)
	for _, file := range fileList.Files {
		files[file.Name] = file.Id
	}

	return files, nil
}

func (c *client) restoreBackupFromDrive() {
	ui.ClearScreen()
	fmt.Println("** Restore Backup from Google Drive **")

	credentialsPath := "keys/credentials.json"
	driveFolderID := "11gN_pH9h0RJkyQ19mZEtJLxVbEyH6ZFt"

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

		res, _, _ := c.sendRequest(api.Request{
			Action: api.ActionRestore,
			Data:   selectedID,
		})

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

	c.conversationView(recipient)
}

func (c *client) conversationView(recipient string) {
	for {
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

		tempFilePath := filepath.Join(os.TempDir(), selectedName)
		if err := logging.DownloadLogFromGoogleDrive(selectedID, tempFilePath, credentialsPath); err != nil {
			fmt.Println("Error al descargar el log:", err)
			return
		}

		decryptedFilePath := tempFilePath + ".dec"
		if err := logging.DecryptFile(tempFilePath, decryptedFilePath, "keys/logs_encryption.key"); err != nil {
			fmt.Println("Error al desencriptar el log:", err)
			return
		}

		content, err := os.ReadFile(decryptedFilePath)
		if err != nil {
			fmt.Println("Error al leer el log desencriptado:", err)
			return
		}

		fmt.Println("\nContenido del log:")
		fmt.Println(string(content))
		fmt.Println("\nPresiona 'q' para volver al menú principal.")
		ui.ReadInput("")

		os.Remove(tempFilePath)
		os.Remove(decryptedFilePath)
		return
	}
}

func (c *client) banMenu() {
	ui.ClearScreen()
	fmt.Println("** Ban/Unban Users **")

	options := []string{"Ban a user", "Unban a user", "Back"}
	choice := ui.PrintMenu("Ban/Unban Menu", options)

	switch choice {
	case 1:
		username := c.selectUser("Select a user to ban")
		if username == "" {
			fmt.Println("No user selected.")
			return
		}

		statusRes, _, _ := c.sendRequest(api.Request{
			Action:   api.ActionCheckBanStatus,
			Username: username,
		})
		if statusRes.Message == "User is banned" {
			fmt.Printf("The user '%s' is already banned.\n", username)
			return
		}

		res, _, _ := c.sendRequest(api.Request{
			Action:   api.ActionBanUser,
			Username: username,
		})
		fmt.Println("Success:", res.Success)
		fmt.Println("Message:", res.Message)

	case 2:
		username := c.selectUser("Select a user to unban")
		if username == "" {
			fmt.Println("No user selected.")
			return
		}

		statusRes, _, _ := c.sendRequest(api.Request{
			Action:   api.ActionCheckBanStatus,
			Username: username,
		})
		if statusRes.Message == "User is not banned" {
			fmt.Printf("The user '%s' is not banned.\n", username)
			return
		}

		res, _, _ := c.sendRequest(api.Request{
			Action:   api.ActionUnbanUser,
			Username: username,
		})
		fmt.Println("Success:", res.Success)
		fmt.Println("Message:", res.Message)

	case 3:
		return
	}
}

func (c *client) selectUser(prompt string) string {
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

	fmt.Println(prompt)
	for i, name := range usernames {
		fmt.Printf("%d. %s\n", i+1, name)
	}

	choice := ui.ReadInt("Select a user")
	if choice < 1 || choice > len(usernames) {
		fmt.Println("Invalid choice.")
		return ""
	}

	return usernames[choice-1]
}

func (c *client) modifyUserRole() {
	ui.ClearScreen()
	fmt.Println("** Modify User Role **")

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

	if len(usernames) == 0 {
		fmt.Println("No users available.")
		return
	}

	fmt.Println("Available Users:")
	for i, name := range usernames {
		fmt.Printf("%d. %s\n", i+1, name)
	}

	choice := ui.ReadInt("Select a user to modify their role")
	if choice < 1 || choice > len(usernames) {
		fmt.Println("Invalid choice.")
		return
	}
	selectedUser := usernames[choice-1]

	roleRes, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionFetchUserRole,
		Username: selectedUser,
	})
	if !roleRes.Success {
		fmt.Println("Error fetching user role:", roleRes.Message)
		return
	}
	currentRole := roleRes.Data

	if currentRole == "admin" {
		fmt.Printf("The user '%s' is an admin. You cannot modify their role.\n", selectedUser)
		return
	}

	fmt.Println("Available roles:")
	fmt.Println("1. normal")
	fmt.Println("2. moderator")
	roleChoice := ui.ReadInt("Select the new role")
	var newRole string
	switch roleChoice {
	case 1:
		newRole = "normal"
	case 2:
		newRole = "moderator"
	default:
		fmt.Println("Invalid role choice.")
		return
	}

	if newRole == currentRole {
		fmt.Printf("The user '%s' already has the role '%s'. No changes were made.\n", selectedUser, currentRole)
		return
	}

	resUpdate, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionModifyUserRole,
		Username: selectedUser,
		Data:     newRole,
	})

	fmt.Println("Success:", resUpdate.Success)
	fmt.Println("Message:", resUpdate.Message)
}

// Corrección de la función deleteUserGroup - Faltaba enviar la solicitud al servidor
func (c *client) deleteUserGroup() {
	ui.ClearScreen()
	fmt.Println("** Eliminar Grupo de Usuarios **")

	// Obtener la lista de grupos
	res, _, _ := c.sendRequest(api.Request{
		Action: api.ActionListUserGroups,
	})
	if !res.Success {
		fmt.Println("Error al listar los grupos:", res.Message)
		return
	}

	var groups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(res.Data), &groups); err != nil {
		fmt.Println("Error al decodificar los grupos:", err)
		return
	}

	if len(groups) == 0 {
		fmt.Println("No hay grupos disponibles.")
		return
	}

	fmt.Println("Grupos disponibles:")
	for i, group := range groups {
		fmt.Printf("%d. %s (ID: %s)\n", i+1, group.Name, group.ID)
	}

	choice := ui.ReadInt("Selecciona un grupo para eliminar")
	if choice < 1 || choice > len(groups) {
		fmt.Println("Opción no válida.")
		return
	}

	// CORREGIDO: Enviar la solicitud para eliminar el grupo
	selectedGroupID := groups[choice-1].ID
	res, _, _ = c.sendRequest(api.Request{
		Action: api.ActionDeleteUserGroup,
		Data:   selectedGroupID,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

// Corrección para la función editUserGroup - Mejorar la selección de miembros
func (c *client) editUserGroup() {
	ui.ClearScreen()
	fmt.Println("** Editar Grupo de Usuarios **")

	// Obtener la lista de grupos
	res, _, _ := c.sendRequest(api.Request{
		Action: api.ActionListUserGroups,
	})
	if !res.Success {
		fmt.Println("Error al listar los grupos:", res.Message)
		return
	}

	var groups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(res.Data), &groups); err != nil {
		fmt.Println("Error al decodificar los grupos:", err)
		return
	}

	if len(groups) == 0 {
		fmt.Println("No hay grupos disponibles.")
		return
	}

	fmt.Println("Grupos disponibles:")
	for i, group := range groups {
		fmt.Printf("%d. %s (ID: %s)\n", i+1, group.Name, group.ID)
	}

	choice := ui.ReadInt("Selecciona un grupo para editar")
	if choice < 1 || choice > len(groups) {
		fmt.Println("Opción no válida.")
		return
	}

	selectedGroup := groups[choice-1]

	// CORREGIDO: Solicitar la lista de usuarios como en createUserGroup
	// Request the list of users from the server
	res, _, _ = c.sendRequest(api.Request{
		Action: api.ActionGetUsernames,
	})
	if !res.Success {
		fmt.Println("Error fetching usernames:", res.Message)
		return
	}

	// Decode the list of usernames
	var usernames []string
	if err := json.Unmarshal([]byte(res.Data), &usernames); err != nil {
		fmt.Println("Error decoding usernames:", err)
		return
	}

	if len(usernames) == 0 {
		fmt.Println("No users available.")
		return
	}

	// Display the list of users
	fmt.Println("Available Users:")
	for i, name := range usernames {
		fmt.Printf("%d. %s\n", i+1, name)
	}

	// Allow the administrator to select multiple users
	var members []string
	fmt.Println("Enter the numbers of the users to add to the group (leave blank to finish):")
	for {
		choice := ui.ReadInput("User number")
		if choice == "" {
			break
		}

		// Convert the input to an integer
		index, err := strconv.Atoi(choice)
		if err != nil || index < 1 || index > len(usernames) {
			fmt.Println("Invalid choice. Please enter a valid number.")
			continue
		}

		// Add the selected user to the group
		selectedUser := usernames[index-1]
		members = append(members, selectedUser)
	}

	group := struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Members []string `json:"members"`
	}{
		ID:      selectedGroup.ID,
		Name:    selectedGroup.Name,
		Members: members,
	}

	groupData, err := json.Marshal(group)
	if err != nil {
		fmt.Println("Error al serializar el grupo:", err)
		return
	}

	res, _, _ = c.sendRequest(api.Request{
		Action:   api.ActionEditUserGroup,
		Username: c.currentUser,
		Data:     string(groupData),
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

// Versión mejorada de listUserGroups con depuración
func (c *client) listUserGroups() {
	ui.ClearScreen()
	fmt.Println("** Listar Grupos de Usuarios **")

	res, _, _ := c.sendRequest(api.Request{
		Action: api.ActionListUserGroups,
	})

	fmt.Printf("DEBUG: Response from server: Success: %v, Message: %s, Data length: %d\n",
		res.Success, res.Message, len(res.Data))

	if !res.Success {
		fmt.Println("Error al listar los grupos:", res.Message)
		return
	}

	// Si la respuesta está vacía
	if res.Data == "" {
		fmt.Println("No hay grupos disponibles (respuesta vacía).")
		return
	}

	fmt.Printf("DEBUG: Raw data: %s\n", res.Data)

	var groups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(res.Data), &groups); err != nil {
		fmt.Println("Error al decodificar los grupos:", err)
		return
	}

	if len(groups) == 0 {
		fmt.Println("No hay grupos disponibles.")
		return
	}

	fmt.Println("Grupos disponibles:")
	for _, group := range groups {
		fmt.Printf("- %s (ID: %s)\n", group.Name, group.ID)
	}
}

// Versión mejorada de createUserGroup para garantizar que se crea correctamente
func (c *client) createUserGroup() {
	ui.ClearScreen()
	fmt.Println("** Create User Group **")

	// Request the group name
	groupName := ui.ReadInput("Enter the group name")
	if groupName == "" {
		fmt.Println("The group name cannot be empty.")
		return
	}

	// Request the list of users from the server
	res, _, _ := c.sendRequest(api.Request{
		Action: api.ActionGetUsernames,
	})
	if !res.Success {
		fmt.Println("Error fetching usernames:", res.Message)
		return
	}

	// Decode the list of usernames
	var usernames []string
	if err := json.Unmarshal([]byte(res.Data), &usernames); err != nil {
		fmt.Println("Error decoding usernames:", err)
		return
	}

	if len(usernames) == 0 {
		fmt.Println("No users available.")
		return
	}

	// Display the list of users
	fmt.Println("Available Users:")
	for i, name := range usernames {
		fmt.Printf("%d. %s\n", i+1, name)
	}

	// Allow the administrator to select multiple users
	var members []string
	fmt.Println("Enter the numbers of the users to add to the group (leave blank to finish):")
	for {
		choice := ui.ReadInput("User number")
		if choice == "" {
			break
		}

		// Convert the input to an integer
		index, err := strconv.Atoi(choice)
		if err != nil || index < 1 || index > len(usernames) {
			fmt.Println("Invalid choice. Please enter a valid number.")
			continue
		}

		// Add the selected user to the group
		selectedUser := usernames[index-1]
		members = append(members, selectedUser)
	}

	// Create the group structure
	group := struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Members []string `json:"members"`
	}{
		ID:      "", // El servidor generará un UUID
		Name:    groupName,
		Members: members,
	}

	// Serializar el grupo
	groupData, err := json.Marshal(group)
	if err != nil {
		fmt.Println("Error serializing the group:", err)
		return
	}

	fmt.Printf("DEBUG: Sending group data: %s\n", string(groupData))

	// Send the request to the server to create the group
	res, _, _ = c.sendRequest(api.Request{
		Action: api.ActionCreateUserGroup,
		Data:   string(groupData),
	})

	// Display the result
	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)

	if res.Success {
		fmt.Println("Group ID:", res.Data)

		// Verificar inmediatamente listando los grupos
		fmt.Println("\nVerificando grupos creados:")
		c.listUserGroups()
	}
}

func (c *client) debugUserGroups() {
	ui.ClearScreen()
	fmt.Println("** Depuración de Grupos de Usuarios **")

	res, _, _ := c.sendRequest(api.Request{
		Action: api.ActionDebugUserGroup,
	})

	fmt.Println("Respuesta del servidor:")
	fmt.Println("Success:", res.Success)
	fmt.Println("Message:", res.Message)
	fmt.Println("Data:", res.Data)
}
