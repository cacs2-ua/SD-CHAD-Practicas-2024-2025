package api

const (
	ActionRegister               = "register"
	ActionLogin                  = "login"
	ActionPublicKeyLogin         = "publicKeyLogin"
	ActionPublicKeyLoginResponse = "publicKeyLoginResponse"
	ActionFetchData              = "fetchData"
	ActionUpdateData             = "updateData"
	ActionLogout                 = "logout"
	ActionRefresh                = "refresh" // new action for token refresh
	ActionBackup                 = "backup"  // new action for database backup
	ActionRestore                = "restore" // new action for database restore

	// New actions for secure messaging functionality
	ActionGetUsernames = "getUsernames"
	ActionSendMessage  = "sendMessage"
	ActionGetMessages  = "getMessages"

	//Actions for polls
	ActionCreatePoll  = "createPoll"
	ActionModifyPoll  = "modifyPoll"
	ActionVoteInPoll  = "voteInPoll"
	ActionViewResults = "viewResults"
	ActionListPolls   = "listPolls"

	// Actions for banning users
	ActionBanUser        = "banUser"
	ActionUnbanUser      = "unbanUser"
	ActionCheckBanStatus = "checkBanStatus"
)

// Request structure for communication between server and client.
type Request struct {
	Action   string `json:"action"`
	Username string `json:"username,omitempty"` // For messaging, this is the recipient or conversation partner
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
	Data     string `json:"data,omitempty"`
	Sender   string `json:"sender,omitempty"` // New field for messaging actions (sender's username)
}

// Response structure for communication between server and client.
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}
