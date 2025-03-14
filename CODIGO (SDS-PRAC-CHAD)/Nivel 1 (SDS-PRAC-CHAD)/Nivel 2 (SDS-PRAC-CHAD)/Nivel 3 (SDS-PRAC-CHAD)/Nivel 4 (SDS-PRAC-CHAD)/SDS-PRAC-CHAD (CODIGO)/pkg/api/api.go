package api

const (
	ActionRegister   = "register"
	ActionLogin      = "login"
	ActionFetchData  = "fetchData"
	ActionUpdateData = "updateData"
	ActionLogout     = "logout"
	ActionRefresh    = "refresh" // new action for token refresh
)

// Request structure for communication between server and client.
type Request struct {
	Action   string `json:"action"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Data     string `json:"data,omitempty"`
}

// Response structure for communication between server and client.
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}
