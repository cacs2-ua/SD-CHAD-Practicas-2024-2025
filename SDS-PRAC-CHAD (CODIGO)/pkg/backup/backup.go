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

const credentialsPath = "keys/credentials.json"
const driveFolderID = "1Ewup_f2O0VgiLXEIIGkQFDTZVHSDgjiE"
const backupDir = "backups"
const dbPath = "data/server.db"

func BackupDatabase() error {
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("error creating backup directory: %v", err)
	}

	epoch := time.Now().Unix()
	backupFile := filepath.Join(backupDir, fmt.Sprintf("server_backup_%d.db", epoch))

	srcFile, err := os.Open(dbPath)
	if err != nil {
		return fmt.Errorf("error opening database file: %v", err)
	}
	defer srcFile.Close()

	destFile, err := os.Create(backupFile)
	if err != nil {
		return fmt.Errorf("error creating backup file: %v", err)
	}

	if _, err := io.Copy(destFile, srcFile); err != nil {
		return fmt.Errorf("error copying database file: %v", err)
	}

	if err := destFile.Close(); err != nil {
		return fmt.Errorf("error closing backup file before encryption: %v", err)
	}

	encryptedBackupFile := backupFile + ".enc"
	if err := encryptFile(backupFile, encryptedBackupFile, "keys/db_encryption.key"); err != nil {
		return fmt.Errorf("error encrypting backup file: %v", err)
	}

	if err := uploadToGoogleDrive(encryptedBackupFile, driveFolderID, credentialsPath); err != nil {
		return fmt.Errorf("error uploading encrypted backup to Google Drive: %v", err)
	}

	// Intentar borrar el .enc hasta 6 veces si está bloqueado
	for i := 0; i < 6; i++ {
		if err := os.Remove(encryptedBackupFile); err != nil {
			if i == 5 {
				return fmt.Errorf("error deleting encrypted backup file after retries: %v", err)
			}
			time.Sleep(500 * time.Millisecond)
		} else {
			break
		}
	}

	// Intentar borrar el .txt hasta 6 veces si está bloqueado
	for i := 0; i < 6; i++ {
		if err := os.Remove(backupFile); err != nil {
			if i == 5 {
				return fmt.Errorf("error deleting plain backup file after retries: %v", err)
			}
			time.Sleep(500 * time.Millisecond)
		} else {
			break
		}
	}

	logging.Log("Backup de base de datos creado")

	return nil
}

func uploadToGoogleDrive(filePath string, folderID string, credentialsPath string) error {
	ctx := context.Background()

	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return fmt.Errorf("error creating Google Drive service: %v", err)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file for upload: %v", err)
	}
	defer file.Close()

	fileMetadata := &drive.File{
		Name:    filepath.Base(filePath),
		Parents: []string{folderID},
	}

	_, err = srv.Files.Create(fileMetadata).Media(file).Do()
	if err != nil {
		return fmt.Errorf("error uploading file to Google Drive: %v", err)
	}

	return nil
}

func DownloadBackupFromGoogleDrive(fileID string, destinationPath string) error {
	backupDir := filepath.Dir(destinationPath)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("error creating backup dir %q: %v", backupDir, err)
	}

	ctx := context.Background()

	srv, err := drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return fmt.Errorf("error creating Google Drive service: %v", err)
	}

	encryptedFilePath := destinationPath + ".enc"

	defer func() { _ = os.Remove(encryptedFilePath) }()

	resp, err := srv.Files.Get(fileID).Download()
	if err != nil {
		return fmt.Errorf("error downloading file from Google Drive: %v", err)
	}
	defer resp.Body.Close()

	encFile, err := os.Create(encryptedFilePath)
	if err != nil {
		return fmt.Errorf("error creating encrypted file: %v", err)
	}
	defer encFile.Close()

	if _, err := io.Copy(encFile, resp.Body); err != nil {
		return fmt.Errorf("error saving encrypted file: %v", err)
	}

	if err := decryptFile(encryptedFilePath, destinationPath, "keys/db_encryption.key"); err != nil {
		return fmt.Errorf("error decrypting file: %v", err)
	}

	return nil
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

func decryptFile(inputPath, outputPath, keyPath string) error {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("error reading decryption key: %v", err)
	}

	keyStr := strings.TrimSpace(string(key))

	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("error decoding decryption key: %v", err)
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

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(inputFile, iv); err != nil {
		return fmt.Errorf("error reading IV: %v", err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return fmt.Errorf("error creating AES cipher: %v", err)
	}

	stream := cipher.NewCFBDecrypter(block, iv)

	reader := &cipher.StreamReader{S: stream, R: inputFile}
	if _, err := io.Copy(outputFile, reader); err != nil {
		return fmt.Errorf("error decrypting file: %v", err)
	}

	return nil
}
