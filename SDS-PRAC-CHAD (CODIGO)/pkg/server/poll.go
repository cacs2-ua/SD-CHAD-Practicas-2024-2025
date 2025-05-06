package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"prac/pkg/api"
	"prac/pkg/crypto"
	"prac/pkg/store"

	"github.com/google/uuid"

	"prac/pkg/logging"
)

// Nombres de los buckets para las encuestas
var bucketPolls = "polls"
var bucketUserVotes = "user_votes"

// Poll representa una encuesta en el sistema
type Poll struct {
	ID         string         `json:"id"`
	Title      string         `json:"title"`
	Options    []string       `json:"options"`
	Votes      map[string]int `json:"votes"`
	EndDate    time.Time      `json:"endDate"`
	CreatedBy  string         `json:"createdBy"`
	Tags       []string       `json:"tags"`
	SingleVote bool           `json:"singlevote"`
	UserGroup  string         `json:"user_group,omitempty"`
}

// UserVote registra que un usuario ha votado en una encuesta específica
type UserVote struct {
	UserID string `json:"userId"`
	PollID string `json:"pollId"`
}

// handleCreatePoll crea una nueva encuesta con las opciones especificadas
func (s *serverImpl) handleCreatePoll(req api.Request, providedAccessToken string) api.Response {

	// Decodificar los datos de la encuesta desde el request
	var poll Poll
	if err := json.Unmarshal([]byte(req.Data), &poll); err != nil {
		return api.Response{Success: false, Message: "Error al decodificar los datos de la encuesta: " + err.Error()}
	}

	// Validación de datos
	if poll.Title == "" {
		return api.Response{Success: false, Message: "El título de la encuesta no puede estar vacío"}
	}
	if len(poll.Options) < 2 {
		return api.Response{Success: false, Message: "La encuesta debe tener al menos 2 opciones"}
	}
	if poll.EndDate.Before(time.Now()) {
		return api.Response{Success: false, Message: "La fecha de finalización debe ser en el futuro"}
	}

	// Validar y limitar los hashtags a un máximo de 3
	if len(poll.Tags) > 3 {
		return api.Response{Success: false, Message: "La encuesta no puede tener más de 3 hashtags"}
	}
	for i, tag := range poll.Tags {
		if !strings.HasPrefix(tag, "#") {
			poll.Tags[i] = "#" + tag // Asegurarse de que cada hashtag comience con #
		}
	}

	// Generar ID único y cifrarlo
	pollUUID := uuid.New().String()
	encryptedPollID, err := crypto.EncryptUUID(pollUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el ID de la encuesta"}
	}

	poll.ID = encryptedPollID
	poll.CreatedBy = req.Username

	// Inicializar votos
	poll.Votes = make(map[string]int)
	for _, option := range poll.Options {
		poll.Votes[option] = 0
	}

	poll.UserGroup = strings.TrimSpace(poll.UserGroup)

	// Serializar encuesta
	pollData, err := json.Marshal(poll)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar la encuesta: " + err.Error()}
	}

	// Guardar encuesta en la base de datos
	keyPollID := store.HashBytes([]byte(pollUUID))
	if err := s.db.Put(bucketPolls, keyPollID, pollData); err != nil {
		return api.Response{Success: false, Message: "Error al guardar la encuesta: " + err.Error()}
	}

	logging.Log(fmt.Sprintf(
		"CREATE_POLL | user=%s | poll_id=%s | title=%q | group=%q | opts=%v | single=%t",
		req.Username, poll.ID, poll.Title, poll.UserGroup, poll.Options, poll.SingleVote))

	return api.Response{
		Success: true,
		Message: "Encuesta creada correctamente",
		Data:    encryptedPollID,
	}
}

func (s *serverImpl) handleModifyPoll(req api.Request, providedAccessToken string) api.Response {
	// Decode the updated poll data from the request
	var updatedPoll Poll
	if err := json.Unmarshal([]byte(req.Data), &updatedPoll); err != nil {
		return api.Response{Success: false, Message: "Error decoding poll data: " + err.Error()}
	}

	// Ensure the poll ID is provided
	if updatedPoll.ID == "" {
		return api.Response{Success: false, Message: "Poll ID is required"}
	}

	// Decrypt the poll ID
	decryptedPollID, err := crypto.DecryptUUID(updatedPoll.ID)
	if err != nil {
		return api.Response{Success: false, Message: "Error decrypting poll ID"}
	}
	keyPoll := store.HashBytes([]byte(decryptedPollID))

	// Retrieve the existing poll
	pollData, err := s.db.Get(bucketPolls, keyPoll)
	if err != nil {
		return api.Response{Success: false, Message: "Poll not found"}
	}

	var existingPoll Poll
	if err := json.Unmarshal(pollData, &existingPoll); err != nil {
		return api.Response{Success: false, Message: "Error decoding existing poll"}
	}

	// Update allowed fields
	if updatedPoll.Title != "" {
		existingPoll.Title = updatedPoll.Title
	}
	if len(updatedPoll.Options) > 0 {
		existingPoll.Options = updatedPoll.Options
	}
	if !updatedPoll.EndDate.IsZero() {
		if updatedPoll.EndDate.Before(time.Now()) {
			return api.Response{Success: false, Message: "End date must be in the future"}
		}
		existingPoll.EndDate = updatedPoll.EndDate
	}

	if strings.TrimSpace(updatedPoll.UserGroup) != "" {
		existingPoll.UserGroup = strings.TrimSpace(updatedPoll.UserGroup)
	}

	existingPoll.SingleVote = updatedPoll.SingleVote

	// Serialize the updated poll
	updatedPollData, err := json.Marshal(existingPoll)
	if err != nil {
		return api.Response{Success: false, Message: "Error serializing updated poll"}
	}

	// Save the updated poll in the database
	if err := s.db.Put(bucketPolls, keyPoll, updatedPollData); err != nil {
		return api.Response{Success: false, Message: "Error saving updated poll"}
	}

	logging.Log(fmt.Sprintf(
		"MODIFY_POLL | user=%s | poll_id=%s | new_title=%q | new_group=%q | new_opts=%v | single=%t",
		req.Username, existingPoll.ID, updatedPoll.Title, updatedPoll.UserGroup, updatedPoll.Options, updatedPoll.SingleVote))

	return api.Response{Success: true, Message: "Poll updated successfully"}
}

// handleVoteInPoll permite a un usuario votar en una encuesta
func (s *serverImpl) handleVoteInPoll(req api.Request, providedAccessToken string) api.Response {

	// Decodificar los datos del voto
	var voteData struct {
		PollID    string   `json:"pollId"`
		Option    string   `json:"option"`
		Options   []string `json:"options"`
		CreatedBy string   `json:"createdBy"`
	}
	if err := json.Unmarshal([]byte(req.Data), &voteData); err != nil {
		return api.Response{Success: false, Message: "Error al decodificar los datos del voto: " + err.Error()}
	}

	// La clave va a ser el ID de la encuesta + el username
	voteKey := store.HashBytes([]byte(voteData.PollID + req.Username))

	// Verificar si el usuario ya ha votado en esta encuesta
	_, err := s.db.Get(bucketUserVotes, voteKey)
	if err == nil {
		return api.Response{Success: false, Message: "Ya has votado en esta encuesta"}
	}

	// Obtener la encuesta
	//fmt.Printf("Intentando recuperar encuesta con ID: %s\n", voteData.PollID)
	decryptedPollId, err := crypto.DecryptUUID(voteData.PollID)
	if err != nil {
		return api.Response{Success: false, Message: "Error el desencriptar"}
	}
	keyPoll := store.HashBytes([]byte(decryptedPollId))
	pollData, err := s.db.Get(bucketPolls, keyPoll)
	if err != nil {
		return api.Response{Success: false, Message: "Error al recuperar encuesta: " + err.Error()}
	}

	var poll Poll
	if err := json.Unmarshal(pollData, &poll); err != nil {
		return api.Response{Success: false, Message: "Error al decodificar la encuesta: " + err.Error()}
	}

	// Verificar si la encuesta ha finalizado
	if poll.EndDate.Before(time.Now()) {
		return api.Response{Success: false, Message: "La encuesta ha finalizado"}
	}

	// Verificar si las opciones de voto son válidas
	if poll.SingleVote { // VOTO ÚNICO
		optionValid := false
		for _, option := range poll.Options {
			if option == voteData.Option {
				optionValid = true
				break
			}
		}
		if voteData.Option == "" {
			optionValid = true // voto en blanco
		}
		if !optionValid {
			return api.Response{Success: false, Message: "Opción de voto inválida"}
		}

		// Registrar voto
		if voteData.Option != "" {
			poll.Votes[voteData.Option]++
		}
	}
	if !poll.SingleVote { // VOTO MÚLTIPLE
		if len(voteData.Options) == 0 {
			return api.Response{Success: false, Message: "Debes seleccionar al menos una opción para votar"}
		}

		// Validar todas las opciones seleccionadas
		for _, selectedOption := range voteData.Options {
			optionValid := false
			for _, availableOption := range poll.Options {
				if selectedOption == availableOption {
					optionValid = true
					break
				}
			}
			if !optionValid {
				return api.Response{Success: false, Message: "Una o más opciones de voto son inválidas"}
			}
		}

		// Registrar todos los votos
		for _, selectedOption := range voteData.Options {
			poll.Votes[selectedOption]++
		}
	}

	// Actualizar la encuesta en la base de datos
	updatedPollData, err := json.Marshal(poll)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar la encuesta actualizada: " + err.Error()}
	}
	if err := s.db.Put(bucketPolls, keyPoll, updatedPollData); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar la encuesta: " + err.Error()}
	}

	// Registrar que el usuario ha votado en esta encuesta
	userVote := UserVote{
		UserID: req.Username,
		PollID: voteData.PollID,
	}
	userVoteData, err := json.Marshal(userVote)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar el registro de voto: " + err.Error()}
	}
	if err := s.db.Put(bucketUserVotes, voteKey, userVoteData); err != nil {
		return api.Response{Success: false, Message: "Error al registrar el voto: " + err.Error()}
	}

	return api.Response{
		Success: true,
		Message: "Voto registrado correctamente",
	}
}

// handleViewResults obtiene los resultados de una encuesta específica
func (s *serverImpl) handleViewResults(req api.Request, providedAccessToken string) api.Response {

	// Obtener el ID de la encuesta
	pollID := req.Data
	key, erro := crypto.DecryptUUID(pollID)
	if erro != nil {
		return api.Response{Success: false, Message: "Error el desencriptar"}
	}
	keyUUID := store.HashBytes([]byte(key))

	// Obtener la encuesta
	pollData, err := s.db.Get(bucketPolls, keyUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Encuesta no encontrada"}
	}

	var poll Poll
	if err := json.Unmarshal(pollData, &poll); err != nil {
		return api.Response{Success: false, Message: "Error al decodificar la encuesta: " + err.Error()}
	}

	if !s.hasAccessToPoll(req.Username, poll) {
		return api.Response{Success: false, Message: "No tienes acceso a esta encuesta"}
	}

	// Serializar los resultados
	resultsData, err := json.Marshal(poll)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar los resultados: " + err.Error()}
	}

	logging.Log(fmt.Sprintf("VIEW_RESULTS | user=%s | poll_id=%s", req.Username, pollID))

	return api.Response{
		Success: true,
		Message: "Resultados obtenidos correctamente",
		Data:    string(resultsData),
	}
}

// handleListPolls obtiene la lista de todas las encuestas disponibles
func (s *serverImpl) handleListPolls(req api.Request, providedAccessToken string) api.Response {
	if req.Username == "" {
		return api.Response{
			Success: false,
			Message: "Authentication required",
		}
	}

	pollKeys, err := s.db.ListKeys(bucketPolls)
	if err != nil {
		if fmt.Sprintf("%v", err) == "bucket not found: "+fmt.Sprintf("%x", store.BucketName(bucketPolls)) {
			return api.Response{
				Success: true,
				Message: "No hay encuestas disponibles",
				Data:    "[]",
			}
		}
		return api.Response{Success: false, Message: "Error al obtener las encuestas: " + err.Error()}
	}

	var polls []Poll
	for _, key := range pollKeys {
		pollData, err := s.db.Get(bucketPolls, key)
		if err != nil {
			fmt.Printf("⚠️ Error al recuperar encuesta con clave %x: %v\n", key, err)
			continue
		}

		var poll Poll
		if err := json.Unmarshal(pollData, &poll); err != nil {
			fmt.Printf("⚠️ Error al decodificar encuesta con clave %x: %v\n", key, err)
			continue
		}

		if !s.hasAccessToPoll(req.Username, poll) {
			continue
		}

		polls = append(polls, poll)
	}

	if len(polls) == 0 {
		return api.Response{Success: true, Message: "No hay encuestas disponibles", Data: "[]"}
	}

	pollsJSON, err := json.Marshal(polls)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar las encuestas: " + err.Error()}
	}

	return api.Response{
		Success: true,
		Message: "Encuestas obtenidas correctamente",
		Data:    string(pollsJSON),
	}
}

// getRoleAndGroup returns the role and user_group for a given username.
func (s *serverImpl) getRoleAndGroup(username string) (string, string, error) {
	userUUID, err := s.lookupUUIDFromUsername(username)
	if err != nil {
		return "", "", err
	}
	key := store.HashBytes([]byte(userUUID))

	roleBytes, err := s.db.Get("cheese_roles", key)
	if err != nil {
		return "", "", err
	}

	groupBytes, err := s.db.Get(bucketUserGroup, key)
	if err != nil {
		// an empty group is a valid state (general polls)
		groupBytes = []byte("")
	}

	return string(roleBytes), string(groupBytes), nil
}

// hasAccessToPoll enforces the “same user_group” rule for non-admin/moderator users.
func (s *serverImpl) hasAccessToPoll(username string, poll Poll) bool {
	role, userGroup, err := s.getRoleAndGroup(username)
	if err != nil {
		return false
	}
	if role == "admin" || role == "moderator" {
		return true
	}

	pollGroup := strings.TrimSpace(poll.UserGroup)
	if pollGroup == "" { // polls without group are public
		return true
	}
	return pollGroup == strings.TrimSpace(userGroup)
}
