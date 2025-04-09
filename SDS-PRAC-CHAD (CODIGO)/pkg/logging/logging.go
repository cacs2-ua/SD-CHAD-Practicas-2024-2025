package logging

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

const (
	logDir          = "logs"                              // Carpeta local para logs
	credentialsPath = "keys/credentials.json"             // Ruta al archivo JSON con las credenciales
	driveFolderID   = "1ka0Ec2EnHcF2qrvk9nsaSpI124jkLMwj" // ID de la carpeta en Google Drive
)

// Log creates a log entry both locally and in Google Drive.
// It appends logs to a daily file and uploads it to Google Drive at the end of the day.
func Log(message string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in Log: %v\n", r)
		}
	}()

	// Asegúrate de que la carpeta local de logs exista.
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Error creating local log directory: %v\n", err)
		return
	}

	// Genera un nombre de archivo basado en la fecha actual (diario).
	today := time.Now().Format("20060102") // Formato YYYYMMDD
	logFileName := fmt.Sprintf("log_%s.txt", today)
	logFilePath := filepath.Join(logDir, logFileName)

	// Abre el archivo en modo append o créalo si no existe.
	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer file.Close()

	// Escribe el mensaje con un timestamp.
	timestamp := time.Now().Format("2006-01-02 15:04:05") // Formato legible
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)
	if _, err := file.WriteString(logEntry); err != nil {
		fmt.Printf("Error writing to log file: %v\n", err)
		return
	}

	// Sube el archivo de log a Google Drive (opcionalmente, puedes hacerlo al final del día).
	if err := uploadToGoogleDrive(logFilePath, driveFolderID); err != nil {
		fmt.Printf("Error uploading log file to Google Drive: %v\n", err)
		return
	}
}

// uploadToGoogleDrive uploads a file to a specific folder in Google Drive.
func uploadToGoogleDrive(filePath, folderID string) error {
	ctx := context.Background()

	// Autentica usando el archivo de credenciales JSON.
	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return fmt.Errorf("error creating Google Drive service: %v", err)
	}

	// Obtener el nombre del archivo.
	fileName := filepath.Base(filePath)

	// Buscar si el archivo ya existe en la carpeta de Google Drive.
	query := fmt.Sprintf("name = '%s' and '%s' in parents and trashed = false", fileName, folderID)
	fileList, err := srv.Files.List().Q(query).Fields("files(id, name)").Do()
	if err != nil {
		return fmt.Errorf("error searching for file in Google Drive: %v", err)
	}

	var fileID string
	if len(fileList.Files) > 0 {
		// Si el archivo ya existe, obtener su ID.
		fileID = fileList.Files[0].Id
	}

	// Abrir el archivo local para subirlo.
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file for upload: %v", err)
	}
	defer file.Close()

	if fileID != "" {
		// Si el archivo existe, actualizar su contenido.
		_, err = srv.Files.Update(fileID, nil).Media(file).Do()
		if err != nil {
			return fmt.Errorf("error updating file in Google Drive: %v", err)
		}
	} else {
		// Si el archivo no existe, crear uno nuevo.
		fileMetadata := &drive.File{
			Name:    fileName,
			Parents: []string{folderID},
		}
		_, err = srv.Files.Create(fileMetadata).Media(file).Do()
		if err != nil {
			return fmt.Errorf("error uploading file to Google Drive: %v", err)
		}
	}

	return nil
}
