package api

const (
	ActionRegister               = "register"
	ActionLogin                  = "login"
	ActionPublicKeyLogin         = "publicKeyLogin"
	ActionPublicKeyLoginResponse = "publicKeyLoginResponse"
	ActionFetchData              = "fetchData"
	ActionUpdateData             = "updateData"
	ActionModifyUserRole         = "modifyUserRole"
	ActionFetchUserRole          = "FetchUserRole"
	ActionLogout                 = "logout"
	ActionRefresh                = "refresh"
	ActionBackup                 = "backup"
	ActionRestore                = "restore"

	ActionGetUsernames = "getUsernames"
	ActionSendMessage  = "sendMessage"
	ActionGetMessages  = "getMessages"

	ActionCreatePoll  = "createPoll"
	ActionModifyPoll  = "modifyPoll"
	ActionVoteInPoll  = "voteInPoll"
	ActionViewResults = "viewResults"
	ActionListPolls   = "listPolls"

	ActionBanUser        = "banUser"
	ActionUnbanUser      = "unbanUser"
	ActionCheckBanStatus = "checkBanStatus"

	// Actions for User Groups
	ActionCreateUserGroup       = "createUserGroup"
	ActionEditUserGroup         = "editUserGroup"
	ActionDeleteUserGroup       = "deleteUserGroup"
	ActionListUserGroups        = "listUserGroups"
	ActionListUserGroupsForUser = "listUserGroupsForUser"
	ActionDebugUserGroup        = "debug_list_groups"
)

type Request struct {
	Action    string `json:"action"`
	Username  string `json:"username,omitempty"`
	Email     string `json:"email,omitempty"`
	Password  string `json:"password,omitempty"`
	Data      string `json:"data,omitempty"`
	Sender    string `json:"sender,omitempty"`
	UserGroup string `json:"user_group,omitempty"`
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}
