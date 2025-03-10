// Package api contains the structures needed for communication between server and client.
package api

const (
	ActionRegister   = "register"
	ActionLogin      = "login"
	ActionFetchData  = "fetchData"
	ActionUpdateData = "updateData"
	ActionLogout     = "logout"
)

// Request and Response structs.
// The Request struct now includes a PublicKey field.
type Request struct {
	Action    string `json:"action"`
	Username  string `json:"username"`
	Password  string `json:"password,omitempty"`
	Token     string `json:"token,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Data      string `json:"data,omitempty"`
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
	Data    string `json:"data,omitempty"`
}
