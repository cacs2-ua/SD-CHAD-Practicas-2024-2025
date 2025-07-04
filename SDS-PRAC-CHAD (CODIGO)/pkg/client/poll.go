package client

import (
	"encoding/json"
	"fmt"
	"prac/pkg/api"
	"prac/pkg/ui"
	"strconv"
	"strings"
	"time"
)

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

type UserVote struct {
	UserID string `json:"userId"`
	PollID string `json:"pollId"`
}

func (c *client) createPoll() {
	ui.ClearScreen()
	fmt.Println("** Crear Nueva Encuesta **")

	title := ui.ReadInput("Título de la encuesta")
	if title == "" {
		fmt.Println("El título no puede estar vacío.")
		return
	}

	userGroup := ui.ReadInput("Asigna un grupo de usuarios (opcional)")

	var options []string
	fmt.Println("Introduce las opciones de voto (deja en blanco para terminar):")
	for i := 1; ; i++ {
		option := ui.ReadInput(fmt.Sprintf("Opción %d", i))
		if option == "" {
			if i < 3 {
				fmt.Println("Debes introducir al menos 2 opciones.")
				continue
			}
			break
		}
		options = append(options, option)
	}

	voteType := ui.ReadInput("¿Encuesta de voto múltiple? (s/n):")
	if voteType != "s" && voteType != "n" {
		fmt.Println("Opción no válida")
		return
	}

	var singleVote bool
	if voteType == "s" {
		singleVote = false
	}
	if voteType == "n" {
		singleVote = true
	}

	var tags []string
	fmt.Println("Introduce hasta 3 hashtags (deja en blanco para terminar):")
	for len(tags) < 3 {
		tag := ui.ReadInput(fmt.Sprintf("Hashtag %d (ejemplo: #politica):", len(tags)+1))
		if tag == "" {
			break
		}
		if !strings.HasPrefix(tag, "#") {
			tag = "#" + tag
		}
		tags = append(tags, tag)
	}

	fmt.Println("Introduce la fecha de finalización (formato: DD/MM/YYYY):")
	dateStr := ui.ReadInput("Fecha")
	fmt.Println("Introduce la hora de finalización (formato: HH:MM):")
	timeStr := ui.ReadInput("Hora")

	endDate, err := time.ParseInLocation("02/01/2006 15:04", dateStr+" "+timeStr, time.Local)
	if err != nil {
		fmt.Println("Formato de fecha u hora inválido:", err)
		return
	}

	poll := Poll{
		Title:      title,
		Options:    options,
		EndDate:    endDate,
		CreatedBy:  c.currentUser,
		Tags:       tags,
		SingleVote: singleVote,
		UserGroup:  strings.TrimSpace(userGroup),
	}

	pollData, err := json.Marshal(poll)
	if err != nil {
		fmt.Println("Error al serializar la encuesta:", err)
		return
	}

	res, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionCreatePoll,
		Username: c.currentUser,
		Data:     string(pollData),
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

func (c *client) modifyPoll() {
	ui.ClearScreen()
	fmt.Println("** Modify Poll **")

	res, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionListPolls,
		Username: c.currentUser,
	})

	if !res.Success {
		fmt.Println("Error fetching polls:", res.Message)
		return
	}

	var polls []Poll
	if err := json.Unmarshal([]byte(res.Data), &polls); err != nil {
		fmt.Println("Error decoding polls:", err)
		return
	}

	if len(polls) == 0 {
		fmt.Println("No polls available to modify.")
		return
	}

	fmt.Println("Available polls to modify:")
	for i, poll := range polls {
		fmt.Printf("%d. %s (ends on %s)\n", i+1, poll.Title, poll.EndDate.Format("02/01/2006 15:04"))
		if len(poll.Tags) > 0 {
			fmt.Printf("   Hashtags: %s\n", strings.Join(poll.Tags, ", "))
		}
		if poll.UserGroup != "" {
			fmt.Printf("   User Group: %s\n", poll.UserGroup)
		}
	}

	choice := ui.ReadInt("Select a poll to modify")
	if choice < 1 || choice > len(polls) {
		fmt.Println("Invalid choice.")
		return
	}

	selectedPoll := polls[choice-1]

	fmt.Printf("Current title: %s\n", selectedPoll.Title)
	fmt.Printf("Current options: %s\n", strings.Join(selectedPoll.Options, ", "))
	fmt.Printf("Current end date: %s\n", selectedPoll.EndDate.Format("02/01/2006 15:04"))
	if selectedPoll.UserGroup != "" {
		fmt.Printf("Current user group: %s\n", selectedPoll.UserGroup)
	}

	newTitle := ui.ReadInput("New title (leave blank to keep):")

	newUserGroup := ui.ReadInput("New user group (leave blank to keep):")

	newOptions := []string{}
	fmt.Println("Enter new options (leave blank to keep current options):")
	for i := 1; ; i++ {
		option := ui.ReadInput(fmt.Sprintf("Option %d", i))
		if option == "" {
			break
		}
		newOptions = append(newOptions, option)
	}

	voteType := ui.ReadInput("Multiple vote? (y/n):")
	if voteType != "y" && voteType != "n" {
		fmt.Println("Opción no válida")
		return
	}

	var singleVote bool
	if voteType == "y" {
		singleVote = false
	}
	if voteType == "n" {
		singleVote = true
	}

	if len(newOptions) > 0 && len(newOptions) < 2 {
		fmt.Println("You must provide at least 2 options.")
		return
	}

	newDateStr := ui.ReadInput("New end date (leave blank to keep):")

	var newEndDate time.Time
	var err error
	if newDateStr != "" {
		newEndDate, err = time.ParseInLocation("02/01/2006 15:04", newDateStr, time.Local)
		if err != nil {
			fmt.Println("Invalid date format:", err)
			return
		}
	}

	updatedPoll := Poll{
		ID:         selectedPoll.ID,
		SingleVote: singleVote,
	}

	if newTitle != "" {
		updatedPoll.Title = newTitle
	}
	if len(newOptions) > 0 {
		updatedPoll.Options = newOptions
	}
	if !newEndDate.IsZero() {
		updatedPoll.EndDate = newEndDate
	}
	if newUserGroup != "" {
		updatedPoll.UserGroup = strings.TrimSpace(newUserGroup)
	}

	updatedPollData, err := json.Marshal(updatedPoll)
	if err != nil {
		fmt.Println("Error serializing updated poll:", err)
		return
	}

	resUpdate, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionModifyPoll,
		Username: c.currentUser,
		Data:     string(updatedPollData),
	})

	fmt.Println("Success:", resUpdate.Success)
	fmt.Println("Message:", resUpdate.Message)
}

func (c *client) voteInPoll() {
	ui.ClearScreen()
	fmt.Println("** Votar en una Encuesta **")

	res, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionListPolls,
		Username: c.currentUser,
	})

	if !res.Success {
		fmt.Println("Error al obtener las encuestas:", res.Message)
		return
	}

	cleanData := strings.ReplaceAll(res.Data, "\u00a0", " ")

	var polls []Poll
	if err := json.Unmarshal([]byte(cleanData), &polls); err != nil {
		fmt.Println("Error al decodificar las encuestas:", err)
		fmt.Println("Datos recibidos:", cleanData)
		return
	}

	if len(polls) == 0 {
		fmt.Println("No hay encuestas disponibles.")
		return
	}

	var activePolls []Poll
	for _, poll := range polls {
		if !poll.EndDate.Before(time.Now()) {
			activePolls = append(activePolls, poll)
		}
	}

	if len(activePolls) == 0 {
		fmt.Println("No hay encuestas activas disponibles.")
		return
	}

	fmt.Println("Encuestas disponibles:")
	for i, poll := range activePolls {
		fmt.Printf("%d. %s (finaliza el %s)\n", i+1, poll.Title, poll.EndDate.Format("02/01/2006 15:04"))
		if len(poll.Tags) > 0 {
			fmt.Printf("   Hashtags: %s\n", strings.Join(poll.Tags, ", "))
		}

		if poll.UserGroup != "" {
			fmt.Printf("   Grupo de Usuario: %s\n", poll.UserGroup)
		}
	}

	choice := ui.ReadInt("Selecciona una encuesta")
	if choice < 1 || choice > len(activePolls) {
		fmt.Println("Elección inválida.")
		return
	}

	selectedPoll := activePolls[choice-1]
	fmt.Printf("Encuesta seleccionada: %s\n", selectedPoll.Title)

	fmt.Println("Opciones de voto:")
	for i, option := range selectedPoll.Options {
		fmt.Printf("%d. %s\n", i+1, option)
	}
	fmt.Println("0. Voto en blanco")

	var selectedOptions []string
	selectedOption := ""

	if selectedPoll.SingleVote {
		optionChoice := ui.ReadInt("Selecciona una opción")
		if optionChoice < 0 || optionChoice > len(selectedPoll.Options) {
			fmt.Println("Elección inválida.")
			return
		}

		if optionChoice != 0 {
			selectedOption = selectedPoll.Options[optionChoice-1]
		}
	} else {
		input := ui.ReadInput("Selecciona las opciones que deseas votar (separadas por comas)")

		if input == "" {
			fmt.Println("No se seleccionó ninguna opción.")
			return
		}

		selections := strings.Split(input, ",")
		selectionMap := make(map[int]bool)

		for _, sel := range selections {
			sel = strings.TrimSpace(sel)
			if sel == "" {
				continue
			}
			num, err := strconv.Atoi(sel)
			if err != nil || num < 0 || num > len(selectedPoll.Options) {
				fmt.Printf("Opción inválida: %s\n", sel)
				return
			}

			if num == 0 {
				continue
			}

			if !selectionMap[num] {
				selectedOptions = append(selectedOptions, selectedPoll.Options[num-1])
				selectionMap[num] = true
			}
		}
	}

	fmt.Println("Opciones seleccionadas:")
	for _, opt := range selectedOptions {
		fmt.Println("-", opt)
	}

	voteData := struct {
		PollID    string   `json:"pollId"`
		Option    string   `json:"option"`
		Options   []string `json:"options"`
		CreatedBy string   `json:"createdBy"`
	}{
		PollID:    selectedPoll.ID,
		Option:    selectedOption,
		Options:   selectedOptions,
		CreatedBy: selectedPoll.CreatedBy,
	}

	voteJSON, err := json.Marshal(voteData)
	if err != nil {
		fmt.Println("Error al serializar el voto:", err)
		return
	}

	voteRes, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionVoteInPoll,
		Username: c.currentUser,
		Data:     string(voteJSON),
	})

	fmt.Println("Éxito:", voteRes.Success)
	fmt.Println("Mensaje:", voteRes.Message)
}

func (c *client) viewResults() {
	ui.ClearScreen()
	fmt.Println("** Ver Resultados de Encuestas **")

	res, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionListPolls,
		Username: c.currentUser,
	})

	if !res.Success {
		fmt.Println("Error al obtener las encuestas:", res.Message)
		return
	}

	cleanData := strings.ReplaceAll(res.Data, "\u00a0", " ")

	var polls []Poll
	if err := json.Unmarshal([]byte(cleanData), &polls); err != nil {
		fmt.Println("Error al decodificar las encuestas:", err)
		fmt.Println("Datos recibidos:", cleanData)
		return
	}

	if len(polls) == 0 {
		fmt.Println("No hay encuestas disponibles.")
		return
	}

	fmt.Println("Encuestas disponibles:")
	for i, poll := range polls {
		status := "Activa"
		if poll.EndDate.Before(time.Now()) {
			status = "Finalizada"
		}
		fmt.Printf("%d. %s (%s)\n", i+1, poll.Title, status)

		if len(poll.Tags) > 0 {
			fmt.Printf("   Hashtags: %s\n", strings.Join(poll.Tags, ", "))
		}

		if poll.UserGroup != "" {
			fmt.Printf("   User Group: %s\n", poll.UserGroup)
		}
	}

	choice := ui.ReadInt("Selecciona una encuesta")
	if choice < 1 || choice > len(polls) {
		fmt.Println("Elección inválida.")
		return
	}

	selectedPoll := polls[choice-1]

	resultsRes, _, _ := c.sendRequest(api.Request{
		Action:   api.ActionViewResults,
		Username: c.currentUser,
		Data:     selectedPoll.ID,
	})

	if !resultsRes.Success {
		fmt.Println("Error al obtener los resultados:", resultsRes.Message)
		return
	}

	cleanResultsData := strings.ReplaceAll(resultsRes.Data, "\u00a0", " ")

	var pollResults Poll
	if err := json.Unmarshal([]byte(cleanResultsData), &pollResults); err != nil {
		fmt.Println("Error al decodificar los resultados:", err)
		fmt.Println("Datos recibidos:", cleanResultsData)
		return
	}

	ui.ClearScreen()
	fmt.Printf("** Resultados de la Encuesta: %s **\n\n", pollResults.Title)
	fmt.Printf("Creada por: %s\n", pollResults.CreatedBy)

	if pollResults.UserGroup != "" {
		fmt.Printf("Grupo de Usuario: %s\n", pollResults.UserGroup)
	}

	status := "Activa"
	if pollResults.EndDate.Before(time.Now()) {
		status = "Finalizada"
	}
	fmt.Printf("Estado: %s\n", status)
	fmt.Printf("Fecha de finalización: %s\n\n", pollResults.EndDate.Format("02/01/2006 15:04"))

	totalVotes := 0
	for _, count := range pollResults.Votes {
		totalVotes += count
	}

	fmt.Printf("Total de votos: %d\n\n", totalVotes)
	fmt.Println("Resultados:")

	for _, option := range pollResults.Options {
		votes := pollResults.Votes[option]
		percentage := 0.0
		if totalVotes > 0 {
			percentage = float64(votes) / float64(totalVotes) * 100
		}
		fmt.Printf("- %s: %d votos (%.1f%%)\n", option, votes, percentage)
	}
}
