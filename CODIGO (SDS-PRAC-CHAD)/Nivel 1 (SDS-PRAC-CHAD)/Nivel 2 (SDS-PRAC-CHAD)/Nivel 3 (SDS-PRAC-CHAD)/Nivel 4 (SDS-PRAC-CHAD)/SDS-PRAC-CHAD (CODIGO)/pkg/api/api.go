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
	Action       string `json:"action"`
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"` // new field for refresh token in requests
	Data         string `json:"data,omitempty"`
}

// Response structure for communication between server and client.
type Response struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	Token        string `json:"token,omitempty"`        // access token
	RefreshToken string `json:"refreshToken,omitempty"` // refresh token
	Data         string `json:"data,omitempty"`
}
