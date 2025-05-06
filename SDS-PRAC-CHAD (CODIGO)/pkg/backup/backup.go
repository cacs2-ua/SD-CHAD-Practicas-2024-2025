package backup

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

	"prac/pkg/logging"
)

const credentialsPath = "keys/credentials.json" // Ruta al archivo JSON con las credenciales
const driveFolderID = "11gN_pH9h0RJkyQ19mZEtJLxVbEyH6ZFt"
const backupDir = "backups"
const dbPath = "data/server.db"

// BackupDatabase creates a backup of the database file and uploads it to Google Drive.
func BackupDatabase() error {
	// Ensure the backup directory exists.
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("error creating backup directory: %v", err)
	}

	// Generate a unique backup file name with a timestamp.
	timestamp := time.Now().Format("20060102_150405")
	backupFile := filepath.Join(backupDir, fmt.Sprintf("server_backup_%s.db", timestamp))

	// Open the source database file.
	srcFile, err := os.Open(dbPath)
	if err != nil {
		return fmt.Errorf("error opening database file: %v", err)
	}
	defer srcFile.Close()

	// Create the destination backup file.
	destFile, err := os.Create(backupFile)
	if err != nil {
		return fmt.Errorf("error creating backup file: %v", err)
	}
	defer destFile.Close()

	// Copy the database file to the backup file.
	if _, err := io.Copy(destFile, srcFile); err != nil {
		return fmt.Errorf("error copying database file: %v", err)
	}

	// Cifrar el archivo de backup.
	encryptedBackupFile := backupFile + ".enc"
	if err := encryptFile(backupFile, encryptedBackupFile, "keys/db_encryption.key"); err != nil {
		return fmt.Errorf("error encrypting backup file: %v", err)
	}

	// Upload the encrypted backup file to Google Drive.
	if err := uploadToGoogleDrive(encryptedBackupFile, driveFolderID, credentialsPath); err != nil {
		return fmt.Errorf("error uploading encrypted backup to Google Drive: %v", err)
	}

	// Eliminar el archivo cifrado localmente después de subirlo.
	if err := os.Remove(encryptedBackupFile); err != nil {
		return fmt.Errorf("error deleting encrypted backup file: %v", err)
	}

	logging.Log("Backup de base de datos creado")

	return nil
}

// uploadToGoogleDrive uploads a file to a specific folder in Google Drive.
func uploadToGoogleDrive(filePath string, folderID string, credentialsPath string) error {
	ctx := context.Background()

	// Authenticate using the credentials JSON file.
	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return fmt.Errorf("error creating Google Drive service: %v", err)
	}

	// Open the file to upload.
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file for upload: %v", err)
	}
	defer file.Close()

	// Create the file metadata.
	fileMetadata := &drive.File{
		Name:    filepath.Base(filePath),
		Parents: []string{folderID},
	}

	// Upload the file.
	_, err = srv.Files.Create(fileMetadata).Media(file).Do()
	if err != nil {
		return fmt.Errorf("error uploading file to Google Drive: %v", err)
	}

	return nil
}

// DownloadBackupFromGoogleDrive downloads a backup file from Google Drive.
func DownloadBackupFromGoogleDrive(fileID string, destinationPath string) error {
	ctx := context.Background()

	// Authenticate using the credentials JSON file.
	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return fmt.Errorf("error creating Google Drive service: %v", err)
	}

	// Descargar el archivo cifrado desde Google Drive.
	encryptedFilePath := destinationPath + ".enc"
	resp, err := srv.Files.Get(fileID).Download()
	if err != nil {
		return fmt.Errorf("error downloading file from Google Drive: %v", err)
	}
	defer resp.Body.Close()

	// Crear el archivo cifrado localmente.
	encFile, err := os.Create(encryptedFilePath)
	if err != nil {
		return fmt.Errorf("error creating encrypted file: %v", err)
	}
	defer encFile.Close()

	// Copiar el contenido al archivo cifrado.
	if _, err := io.Copy(encFile, resp.Body); err != nil {
		return fmt.Errorf("error saving encrypted file: %v", err)
	}

	// Descifrar el archivo.
	if err := decryptFile(encryptedFilePath, destinationPath, "keys/db_encryption.key"); err != nil {
		return fmt.Errorf("error decrypting file: %v", err)
	}

	// Eliminar el archivo cifrado localmente después de descifrarlo.
	if err := os.Remove(encryptedFilePath); err != nil {
		return fmt.Errorf("error deleting encrypted file: %v", err)
	}

	return nil
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

// decryptFile decrypts a file using AES encryption.
func decryptFile(inputPath, outputPath, keyPath string) error {
	// Leer la clave de descifrado desde el archivo.
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("error reading decryption key: %v", err)
	}

	// Eliminar saltos de línea y espacios en blanco de la clave.
	keyStr := strings.TrimSpace(string(key))

	// Convertir la clave de descifrado a bytes.
	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("error decoding decryption key: %v", err)
	}

	// Abrir el archivo de entrada.
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

	// Leer el IV desde el archivo de entrada.
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(inputFile, iv); err != nil {
		return fmt.Errorf("error reading IV: %v", err)
	}

	// Crear un bloque AES.
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return fmt.Errorf("error creating AES cipher: %v", err)
	}

	// Crear un stream de descifrado.
	stream := cipher.NewCFBDecrypter(block, iv)

	// Descifrar y escribir los datos.
	reader := &cipher.StreamReader{S: stream, R: inputFile}
	if _, err := io.Copy(outputFile, reader); err != nil {
		return fmt.Errorf("error decrypting file: %v", err)
	}

	return nil
}
