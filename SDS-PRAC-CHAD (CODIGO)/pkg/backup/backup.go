package backup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// BackupDatabase creates a backup of the database file.
func BackupDatabase(dbPath string, backupDir string) error {
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

	return nil
}
