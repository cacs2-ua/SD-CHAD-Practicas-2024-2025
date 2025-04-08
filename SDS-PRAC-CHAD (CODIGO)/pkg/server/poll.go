package server

import (
	"encoding/json"
	"log"
	"time"

	"prac/pkg/api"
	"prac/pkg/store"

	"github.com/google/uuid"
	"go.etcd.io/bbolt"
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

	// Decodificar los datos de la encuesta
	var poll Poll
	if err := json.Unmarshal([]byte(req.Data), &poll); err != nil {
		return api.Response{Success: false, Message: "Error al decodificar los datos de la encuesta: " + err.Error()}
	}

	// Validar los datos de la encuesta
	if poll.Title == "" {
		return api.Response{Success: false, Message: "El título de la encuesta no puede estar vacío"}
	}
	if len(poll.Options) < 2 {
		return api.Response{Success: false, Message: "La encuesta debe tener al menos 2 opciones"}
	}
	if poll.EndDate.Before(time.Now()) {
		return api.Response{Success: false, Message: "La fecha de finalización debe ser en el futuro"}
	}

	// Generar un ID único para la encuesta
	poll.ID = uuid.New().String()
	poll.CreatedBy = req.Username

	// Inicializar el mapa de votos
	poll.Votes = make(map[string]int)
	for _, option := range poll.Options {
		poll.Votes[option] = 0
	}

	// Serializar la encuesta
	pollData, err := json.Marshal(poll)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar la encuesta: " + err.Error()}
	}

	// Guardar la encuesta en la base de datos
	bs, ok := s.db.(*store.BboltStore)
	if !ok {
		return api.Response{Success: false, Message: "Error al acceder a la base de datos"}
	}

	// Crear los buckets si no existen
	err = bs.DB.Update(func(tx *bbolt.Tx) error {
		// Crear bucket para encuestas
		_, err := tx.CreateBucketIfNotExists(store.BucketName(bucketPolls))
		if err != nil {
			return err
		}
		// Crear bucket para votos de usuarios
		_, err = tx.CreateBucketIfNotExists(store.BucketName(bucketUserVotes))
		return err
	})
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear los buckets: " + err.Error()}
	}

	// Guardar la encuesta
	if err := s.db.Put(bucketPolls, []byte(poll.ID), pollData); err != nil {
		return api.Response{Success: false, Message: "Error al guardar la encuesta: " + err.Error()}
	}

	return api.Response{
		Success: true,
		Message: "Encuesta creada correctamente",
		Data:    poll.ID,
	}
}

// handleVoteInPoll permite a un usuario votar en una encuesta
func (s *serverImpl) handleVoteInPoll(req api.Request, providedAccessToken string) api.Response {
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
	pollData, err := s.db.Get(bucketPolls, []byte(voteData.PollID))
	if err != nil {
		return api.Response{Success: false, Message: "Encuesta no encontrada"}
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
func (s *serverImpl) handleListPolls(req api.Request, providedAccessToken string) api.Response {
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

	//_, err := s.lookupUUIDFromUsername(req.Username)

	// Obtener todas las encuestas
	bs, ok := s.db.(*store.BboltStore)
	if !ok {
		return api.Response{Success: false, Message: "Error al acceder a la base de datos"}
	}

	var polls []Poll
	err := bs.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(store.BucketName(bucketPolls))
		if b == nil {
			return nil // No hay encuestas
		}

		return b.ForEach(func(k, v []byte) error {
			var poll Poll
			if err := json.Unmarshal(v, &poll); err != nil {
				return err
			}
			polls = append(polls, poll)
			return nil
		})
	})
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener las encuestas: " + err.Error()}
	}

	// Serializar la lista de encuestas
	pollsData, err := json.Marshal(polls)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar las encuestas: " + err.Error()}
	}

	return api.Response{
		Success: true,
		Message: "Encuestas obtenidas correctamente",
		Data:    string(pollsData),
	}
}

func (s *serverImpl) handleListPolls2(req api.Request, providedAccessToken string) api.Response {
	// Verificar si el usuario está autenticado
	/*if req.Username == "" || providedAccessToken == "" {
		return api.Response{Success: false, Message: "No estás autenticado"}
	}*/

	// Obtener el UUID del usuario
	_, err := s.lookupUUIDFromUsername(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	// Obtener la base de datos BoltDB
	bs, ok := s.db.(*store.BboltStore)
	if !ok {
		return api.Response{Success: false, Message: "Error al acceder a la base de datos"}
	}

	// Obtener todas las encuestas
	var polls []Poll

	err = bs.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(store.BucketName(bucketPolls))
		if b == nil {
			log.Println("Bucket de encuestas no encontrado")
			return nil // No hay encuestas, no es un error
		}

		return b.ForEach(func(k, v []byte) error {
			log.Printf("Clave: %s, Valor RAW: %s\n", k, v) // Log para depuración

			var poll Poll
			if err := json.Unmarshal(v, &poll); err != nil {
				log.Printf("Error al deserializar la encuesta con clave %s: %v\n", k, err)
				return err
			}

			polls = append(polls, poll)
			return nil
		})
	})

	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener las encuestas: " + err.Error()}
	}

	// Serializar la lista de encuestas
	pollsData, err := json.Marshal(polls)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar las encuestas: " + err.Error()}
	}

	return api.Response{
		Success: true,
		Message: "Encuestas obtenidas correctamente",
		Data:    string(pollsData),
	}
}
