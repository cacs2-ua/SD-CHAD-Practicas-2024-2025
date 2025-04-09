package logging

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

const (
	logDir            = "logs"                              // Carpeta local para logs
	credentialsPath   = "keys/credentials.json"             // Ruta al archivo JSON con las credenciales
	driveFolderID     = "1ka0Ec2EnHcF2qrvk9nsaSpI124jkLMwj" // ID de la carpeta en Google Drive
	encryptionKeyPath = "keys/logs_encryption.key"          // Ruta a la clave de cifrado
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

	// Cifrar el archivo de log antes de subirlo a Google Drive.
	encryptedFilePath := logFilePath + ".enc"
	if err := encryptFile(logFilePath, encryptedFilePath, encryptionKeyPath); err != nil {
		fmt.Printf("Error encrypting log file: %v\n", err)
		return
	}

	// Sube el archivo cifrado a Google Drive.
	if err := uploadToGoogleDrive(encryptedFilePath, driveFolderID); err != nil {
		fmt.Printf("Error uploading encrypted log file to Google Drive: %v\n", err)
		return
	}

	// PRODUCCION
	if err := uploadToGoogleDrive(logFilePath, driveFolderID); err != nil {
		fmt.Printf("Error uploading plain text log file to Google Drive: %v\n", err)
		return
	}

	// Elimina el archivo cifrado localmente después de subirlo.
	if err := os.Remove(encryptedFilePath); err != nil {
		fmt.Printf("Error deleting encrypted log file: %v\n", err)
	}
}

// encryptFile encrypts a file using AES encryption.
func encryptFile(inputPath, outputPath, keyPath string) error {
	// Leer la clave de cifrado desde el archivo.
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("error reading encryption key: %v", err)
	}

	// Eliminar saltos de línea y espacios en blanco de la clave.
	keyStr := strings.TrimSpace(string(key))

	// Convertir la clave de cifrado a bytes.
	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("error decoding encryption key: %v", err)
	}

	// Leer el archivo de entrada.
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inputFile.Close()

	// Crear el archivo de salida.
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outputFile.Close()

	// Crear un bloque AES.
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return fmt.Errorf("error creating AES cipher: %v", err)
	}

	// Crear un IV aleatorio.
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("error generating IV: %v", err)
	}

	// Escribir el IV al principio del archivo de salida.
	if _, err := outputFile.Write(iv); err != nil {
		return fmt.Errorf("error writing IV to output file: %v", err)
	}

	// Crear un stream de cifrado.
	stream := cipher.NewCFBEncrypter(block, iv)

	// Cifrar y escribir los datos.
	writer := &cipher.StreamWriter{S: stream, W: outputFile}
	if _, err := io.Copy(writer, inputFile); err != nil {
		return fmt.Errorf("error encrypting file: %v", err)
	}

	return nil
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

func DecryptFile(inputPath, outputPath, keyPath string) error {
	// Leer la clave de desencriptación desde el archivo.
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("error leyendo la clave de desencriptación: %v", err)
	}

	// Eliminar saltos de línea y espacios en blanco de la clave.
	keyStr := strings.TrimSpace(string(key))

	// Convertir la clave de desencriptación a bytes.
	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("error decodificando la clave de desencriptación: %v", err)
	}

	// Abrir el archivo de entrada.
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("error abriendo el archivo de entrada: %v", err)
	}
	defer inputFile.Close()

	// Crear el archivo de salida.
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creando el archivo de salida: %v", err)
	}
	defer outputFile.Close()

	// Leer el IV desde el archivo de entrada.
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(inputFile, iv); err != nil {
		return fmt.Errorf("error leyendo el IV: %v", err)
	}

	// Crear un bloque AES.
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return fmt.Errorf("error creando el cifrador AES: %v", err)
	}

	// Crear un stream de desencriptación.
	stream := cipher.NewCFBDecrypter(block, iv)

	// Desencriptar y escribir los datos.
	reader := &cipher.StreamReader{S: stream, R: inputFile}
	if _, err := io.Copy(outputFile, reader); err != nil {
		return fmt.Errorf("error desencriptando el archivo: %v", err)
	}

	return nil
}

func DownloadLogFromGoogleDrive(fileID, destinationPath, credentialsPath string) error {
	ctx := context.Background()

	// Autenticar usando el archivo de credenciales JSON.
	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return fmt.Errorf("error creando el servicio de Google Drive: %v", err)
	}

	// Descargar el archivo desde Google Drive.
	resp, err := srv.Files.Get(fileID).Download()
	if err != nil {
		return fmt.Errorf("error descargando el archivo desde Google Drive: %v", err)
	}
	defer resp.Body.Close()

	// Crear el archivo de destino.
	destFile, err := os.Create(destinationPath)
	if err != nil {
		return fmt.Errorf("error creando el archivo de destino: %v", err)
	}
	defer destFile.Close()

	// Copiar el contenido al archivo de destino.
	if _, err := io.Copy(destFile, resp.Body); err != nil {
		return fmt.Errorf("error guardando el archivo en el destino: %v", err)
	}

	return nil
}
