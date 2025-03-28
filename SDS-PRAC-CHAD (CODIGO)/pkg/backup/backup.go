package backup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
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

	// Upload the backup file to Google Drive.
	if err := uploadToGoogleDrive(backupFile, driveFolderID, credentialsPath); err != nil {
		return fmt.Errorf("error uploading backup to Google Drive: %v", err)
	}

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

	// Get the file from Google Drive.
	resp, err := srv.Files.Get(fileID).Download()
	if err != nil {
		return fmt.Errorf("error downloading file from Google Drive: %v", err)
	}
	defer resp.Body.Close()

	// Create the destination file.
	destFile, err := os.Create(destinationPath)
	if err != nil {
		return fmt.Errorf("error creating destination file: %v", err)
	}
	defer destFile.Close()

	// Copy the file content to the destination file.
	if _, err := io.Copy(destFile, resp.Body); err != nil {
		return fmt.Errorf("error saving file to destination: %v", err)
	}

	return nil
}
