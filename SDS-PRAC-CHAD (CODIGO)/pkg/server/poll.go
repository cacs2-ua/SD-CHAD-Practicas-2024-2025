package server

import (
	"encoding/json"
	"fmt"
	"time"

	"prac/pkg/api"
	"prac/pkg/crypto"
	"prac/pkg/store"
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
	// 1. Autenticación básica
	/*if req.Username == "" || providedAccessToken == "" {
		return api.Response{Success: false, Message: "No estás autenticado"}
	}

	// 2. Obtener el UUID del usuario y validar el token
	decryptedUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	if !s.isAccessTokenValid(decryptedUUID, providedAccessToken) {
		return api.Response{Success: false, Message: "Token de acceso inválido o expirado"}
	}*/

	// 3. Decodificar los datos de la encuesta desde el request
	var poll Poll
	if err := json.Unmarshal([]byte(req.Data), &poll); err != nil {
		return api.Response{Success: false, Message: "Error al decodificar los datos de la encuesta: " + err.Error()}
	}

	// 4. Validación de datos
	if poll.Title == "" {
		return api.Response{Success: false, Message: "El título de la encuesta no puede estar vacío"}
	}
	if len(poll.Options) < 2 {
		return api.Response{Success: false, Message: "La encuesta debe tener al menos 2 opciones"}
	}
	if poll.EndDate.Before(time.Now()) {
		return api.Response{Success: false, Message: "La fecha de finalización debe ser en el futuro"}
	}

	// 5. Generar ID único y cifrarlo
	//pollUUID := uuid.New().String()
	pollUUID, err := s.lookupUUIDFromUsername(poll.CreatedBy)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	encryptedPollID, err := crypto.EncryptUUID(pollUUID)
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el ID de la encuesta"}
	}

	poll.ID = encryptedPollID
	poll.CreatedBy = req.Username

	// 6. Inicializar votos
	poll.Votes = make(map[string]int)
	for _, option := range poll.Options {
		poll.Votes[option] = 0
	}

	// 7. Serializar encuesta
	pollData, err := json.Marshal(poll)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar la encuesta: " + err.Error()}
	}

	// 8. Guardar encuesta en la base de datos
	keyPollID := store.HashBytes([]byte(pollUUID)) // Se guarda usando el hash del ID original

	if err := s.db.Put(bucketPolls, keyPollID, pollData); err != nil {
		return api.Response{Success: false, Message: "Error al guardar la encuesta: " + err.Error()}
	}

	// 9. Confirmar guardado
	_, err = s.db.Get(bucketPolls, keyPollID)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar la encuesta guardada: " + err.Error()}
	}

	// 10. Respuesta con ID cifrado
	return api.Response{
		Success: true,
		Message: "Encuesta creada correctamente",
		Data:    encryptedPollID,
	}
}

// handleVoteInPoll permite a un usuario votar en una encuesta
func (s *serverImpl) handleVoteInPoll(req api.Request, providedAccessToken string) api.Response {
	/*if req.Username == "" || providedAccessToken == "" {
		return api.Response{Success: false, Message: "No estás autenticado"}
	}

	// Verificar el token de acceso
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	if !s.isAccessTokenValid(decryptedUUID, providedAccessToken) {
		return api.Response{Success: false, Message: "Token de acceso inválido o expirado"}
	}*/
	decryptedUUID, _ := s.lookupUUIDFromUsername(req.Username)

	// Decodificar los datos del voto
	var voteData struct {
		PollID string `json:"pollId"`
		Option string `json:"option"`
	}
	if err := json.Unmarshal([]byte(req.Data), &voteData); err != nil {
		return api.Response{Success: false, Message: "Error al decodificar los datos del voto: " + err.Error()}
	}

	// Verificar si el usuario ya ha votado en esta encuesta
	userVoteKey := decryptedUUID + ":" + voteData.PollID
	_, err := s.db.Get(bucketUserVotes, []byte(userVoteKey))
	if err == nil {
		return api.Response{Success: false, Message: "Ya has votado en esta encuesta"}
	}

	// Obtener la encuesta
	fmt.Printf("Intentando recuperar encuesta con ID: %s\n", voteData.PollID)
	pollData, err := s.db.Get(bucketPolls, []byte(voteData.PollID))
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
	if !optionValid {
		return api.Response{Success: false, Message: "Opción de voto inválida"}
	}

	// Incrementar el contador de votos para la opción seleccionada
	poll.Votes[voteData.Option]++

	// Actualizar la encuesta en la base de datos
	updatedPollData, err := json.Marshal(poll)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar la encuesta actualizada: " + err.Error()}
	}
	if err := s.db.Put(bucketPolls, []byte(poll.ID), updatedPollData); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar la encuesta: " + err.Error()}
	}

	// Registrar que el usuario ha votado en esta encuesta
	userVote := UserVote{
		UserID: decryptedUUID,
		PollID: voteData.PollID,
	}
	userVoteData, err := json.Marshal(userVote)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar el registro de voto: " + err.Error()}
	}
	if err := s.db.Put(bucketUserVotes, []byte(userVoteKey), userVoteData); err != nil {
		return api.Response{Success: false, Message: "Error al registrar el voto: " + err.Error()}
	}

	return api.Response{
		Success: true,
		Message: "Voto registrado correctamente",
	}
}

// handleViewResults obtiene los resultados de una encuesta específica
func (s *serverImpl) handleViewResults(req api.Request, providedAccessToken string) api.Response {
	/*if req.Username == "" || providedAccessToken == "" {
		return api.Response{Success: false, Message: "No estás autenticado"}
	}

	// Verificar el token de acceso
	decryptedUUID, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	if !s.isAccessTokenValid(decryptedUUID, providedAccessToken) {
		return api.Response{Success: false, Message: "Token de acceso inválido o expirado"}
	}*/

	// Obtener el ID de la encuesta
	pollID := req.Data

	// Obtener la encuesta
	pollData, err := s.db.Get(bucketPolls, []byte(pollID))
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

	fmt.Printf("🔍 Claves encontradas en bucketPolls: %d\n", len(pollKeys))

	var polls []Poll
	for _, key := range pollKeys {
		fmt.Printf("Intentando recuperar clave: %x\n", key)

		decryptedUUID, err := s.lookupUUIDFromUsername(req.Username)
		if err != nil {
			return api.Response{Success: false, Message: "User not found"}
		}
		keyUUID := store.HashBytes([]byte(decryptedUUID))

		pollData, err := s.db.Get(bucketPolls, keyUUID)
		if err != nil {
			fmt.Printf("⚠️ Error al recuperar encuesta con clave %x: %v\n", key, err)
			continue
		}

		var poll Poll
		if err := json.Unmarshal(pollData, &poll); err != nil {
			fmt.Printf("⚠️ Error al decodificar encuesta con clave %x: %v\n", key, err)
			continue
		}

		fmt.Printf("✅ Encuesta recuperada: %s\n", poll.Title)

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
