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

func Log(message string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in Log: %v\n", r)
		}
	}()

	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Error creating local log directory: %v\n", err)
		return
	}

	today := time.Now().Format("20060102")
	logFileName := fmt.Sprintf("log_%s.txt", today)
	logFilePath := filepath.Join(logDir, logFileName)

	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer file.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)
	if _, err := file.WriteString(logEntry); err != nil {
		fmt.Printf("Error writing to log file: %v\n", err)
		return
	}

	encryptedFilePath := logFilePath + ".enc"
	if err := encryptFile(logFilePath, encryptedFilePath, encryptionKeyPath); err != nil {
		fmt.Printf("Error encrypting log file: %v\n", err)
		return
	}

	if err := uploadToGoogleDrive(encryptedFilePath, driveFolderID); err != nil {
		fmt.Printf("Error uploading encrypted log file to Google Drive: %v\n", err)
		return
	}

	if err := uploadToGoogleDrive(logFilePath, driveFolderID); err != nil {
		fmt.Printf("Error uploading plain text log file to Google Drive: %v\n", err)
		return
	}

	if err := os.Remove(encryptedFilePath); err != nil {
		fmt.Printf("Error deleting encrypted log file: %v\n", err)
	}
}

func encryptFile(inputPath, outputPath, keyPath string) error {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("error reading encryption key: %v", err)
	}

	keyStr := strings.TrimSpace(string(key))

	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("error decoding encryption key: %v", err)
	}

	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outputFile.Close()

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return fmt.Errorf("error creating AES cipher: %v", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("error generating IV: %v", err)
	}

	if _, err := outputFile.Write(iv); err != nil {
		return fmt.Errorf("error writing IV to output file: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)

	writer := &cipher.StreamWriter{S: stream, W: outputFile}
	if _, err := io.Copy(writer, inputFile); err != nil {
		return fmt.Errorf("error encrypting file: %v", err)
	}

	return nil
}

func uploadToGoogleDrive(filePath, folderID string) error {
	ctx := context.Background()

	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return fmt.Errorf("error creating Google Drive service: %v", err)
	}

	fileName := filepath.Base(filePath)

	query := fmt.Sprintf("name = '%s' and '%s' in parents and trashed = false", fileName, folderID)
	fileList, err := srv.Files.List().Q(query).Fields("files(id, name)").Do()
	if err != nil {
		return fmt.Errorf("error searching for file in Google Drive: %v", err)
	}

	var fileID string
	if len(fileList.Files) > 0 {
		fileID = fileList.Files[0].Id
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file for upload: %v", err)
	}
	defer file.Close()

	if fileID != "" {
		_, err = srv.Files.Update(fileID, nil).Media(file).Do()
		if err != nil {
			return fmt.Errorf("error updating file in Google Drive: %v", err)
		}
	} else {
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
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("error leyendo la clave de desencriptación: %v", err)
	}

	keyStr := strings.TrimSpace(string(key))

	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("error decodificando la clave de desencriptación: %v", err)
	}

	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("error abriendo el archivo de entrada: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creando el archivo de salida: %v", err)
	}
	defer outputFile.Close()

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(inputFile, iv); err != nil {
		return fmt.Errorf("error leyendo el IV: %v", err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return fmt.Errorf("error creando el cifrador AES: %v", err)
	}

	stream := cipher.NewCFBDecrypter(block, iv)

	reader := &cipher.StreamReader{S: stream, R: inputFile}
	if _, err := io.Copy(outputFile, reader); err != nil {
		return fmt.Errorf("error desencriptando el archivo: %v", err)
	}

	return nil
}

func DownloadLogFromGoogleDrive(fileID, destinationPath, credentialsPath string) error {
	ctx := context.Background()

	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return fmt.Errorf("error creando el servicio de Google Drive: %v", err)
	}

	resp, err := srv.Files.Get(fileID).Download()
	if err != nil {
		return fmt.Errorf("error descargando el archivo desde Google Drive: %v", err)
	}
	defer resp.Body.Close()

	destFile, err := os.Create(destinationPath)
	if err != nil {
		return fmt.Errorf("error creando el archivo de destino: %v", err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, resp.Body); err != nil {
		return fmt.Errorf("error guardando el archivo en el destino: %v", err)
	}

	return nil
}
