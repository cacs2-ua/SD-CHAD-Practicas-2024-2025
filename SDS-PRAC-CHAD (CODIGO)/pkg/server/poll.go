package server

import (
	"encoding/json"
	"fmt"
	"time"

	"prac/pkg/api"
	"prac/pkg/crypto"
	"prac/pkg/store"

	"github.com/google/uuid"
)

// Nombres de los buckets para las encuestas
var bucketPolls = "polls"
var bucketUserVotes = "user_votes"

// Poll representa una encuesta en el sistema
type Poll struct {
	ID        string         `json:"id"`
	Title     string         `json:"title"`
	Options   []string       `json:"options"`
	Votes     map[string]int `json:"votes"`
	EndDate   time.Time      `json:"endDate"`
	CreatedBy string         `json:"createdBy"`
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

	// Serializar encuesta
	pollData, err := json.Marshal(poll)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar la encuesta: " + err.Error()}
	}

	// Guardar encuesta en la base de datos
	keyPollID := store.HashBytes([]byte(pollUUID)) // Se guarda usando el hash del ID original

	if err := s.db.Put(bucketPolls, keyPollID, pollData); err != nil {
		return api.Response{Success: false, Message: "Error al guardar la encuesta: " + err.Error()}
	}

	// Confirmar guardado
	_, err = s.db.Get(bucketPolls, keyPollID)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar la encuesta guardada: " + err.Error()}
	}

	// Respuesta con ID cifrado
	return api.Response{
		Success: true,
		Message: "Encuesta creada correctamente",
		Data:    encryptedPollID,
	}
}

// handleVoteInPoll permite a un usuario votar en una encuesta
func (s *serverImpl) handleVoteInPoll(req api.Request, providedAccessToken string) api.Response {

	// Decodificar los datos del voto
	var voteData struct {
		PollID    string `json:"pollId"`
		Option    string `json:"option"`
		CreatedBy string `json:"createdBy"`
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

	// Verificar si la opción es válida
	optionValid := false
	for _, option := range poll.Options {
		if option == voteData.Option {
			optionValid = true
			break
		}
	}
	if voteData.Option == "" {
		optionValid = true
	}
	if !optionValid {
		return api.Response{Success: false, Message: "Opción de voto inválida"}
	}

	if voteData.Option != "" {
		// Incrementar el contador de votos para la opción seleccionada
		poll.Votes[voteData.Option]++

		// Actualizar la encuesta en la base de datos
		updatedPollData, err := json.Marshal(poll)
		if err != nil {
			return api.Response{Success: false, Message: "Error al serializar la encuesta actualizada: " + err.Error()}
		}
		if err := s.db.Put(bucketPolls, keyPoll, updatedPollData); err != nil {
			return api.Response{Success: false, Message: "Error al actualizar la encuesta: " + err.Error()}
		}
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

	// Serializar los resultados
	resultsData, err := json.Marshal(poll)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar los resultados: " + err.Error()}
	}

	return api.Response{
		Success: true,
		Message: "Resultados obtenidos correctamente",
		Data:    string(resultsData),
	}
}

// handleListPolls obtiene la lista de todas las encuestas disponibles
func (s *serverImpl) handleListPolls(req api.Request, providedAccessToken string) api.Response {
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

	//fmt.Printf("🔍 Claves encontradas en bucketPolls: %d\n", len(pollKeys))

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

		//fmt.Printf("✅ Encuesta recuperada: %s\n", poll.Title)

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
