package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// PrintMenu prints a menu and asks the user to select an option.
func PrintMenu(title string, options []string) int {
	fmt.Print(title, "\n\n")
	for i, option := range options {
		fmt.Printf("%d. %s\n", i+1, option)
	}
	fmt.Print("\nSelect an option: ")

	var choice int
	for {
		_, err := fmt.Scanln(&choice)
		if err == nil && choice >= 1 && choice <= len(options) {
			break
		}
		fmt.Println("Invalid option, please try again.")
		fmt.Print("Select an option: ")
	}
	return choice
}

// ReadInput asks the user for input and returns it as a string.
func ReadInput(prompt string) string {
	fmt.Print(prompt + ": ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

// ReadPassword asks the user for password input and masks the input with asterisks.
func ReadPassword(prompt string) string {
	fmt.Print(prompt + ": ")
	// Set terminal to raw mode.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Error setting terminal to raw mode:", err)
		return ""
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	var password []rune
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			break
		}
		// Break on newline or carriage return.
		if buf[0] == '\r' || buf[0] == '\n' {
			break
		}
		// Handle backspace (8 or 127).
		if buf[0] == 8 || buf[0] == 127 {
			if len(password) > 0 {
				password = password[:len(password)-1]
				// Move cursor back, print space, move cursor back again.
				fmt.Print("\b \b")
			}
			continue
		}
		// Append character and print asterisk.
		password = append(password, rune(buf[0]))
		fmt.Print("*")
	}
	fmt.Println()
	return string(password)
}

// Confirm asks the user for a yes/no confirmation.
func Confirm(message string) bool {
	for {
		fmt.Print(message + " (Y/N): ")
		var response string
		fmt.Scanln(&response)
		response = strings.ToUpper(strings.TrimSpace(response))
		if response == "Y" {
			return true
		} else if response == "N" {
			return false
		}
		fmt.Println("Invalid response, please enter Y or N.")
	}
}

// ClearScreen clears the terminal screen.
func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

// Pause shows a message and waits for the user to press Enter.
func Pause(prompt string) {
	fmt.Println(prompt)
	bufio.NewScanner(os.Stdin).Scan()
}

// ReadInt asks the user for an integer and validates the input.
func ReadInt(prompt string) int {
	for {
		fmt.Print(prompt + ": ")
		var value int
		_, err := fmt.Scanln(&value)
		if err == nil {
			return value
		}
		fmt.Println("Invalid value, please enter an integer.")
		bufio.NewScanner(os.Stdin).Scan()
	}
}

// ReadFloat asks the user for a float and validates the input.
func ReadFloat(prompt string) float64 {
	for {
		fmt.Print(prompt + ": ")
		var value float64
		_, err := fmt.Scanln(&value)
		if err == nil {
			return value
		}
		fmt.Println("Invalid value, please enter a number.")
		bufio.NewScanner(os.Stdin).Scan()
	}
}

// ReadMultiline reads multiple lines until the user enters an empty line.
func ReadMultiline(prompt string) string {
	fmt.Println(prompt + " (enter an empty line to finish):")
	scanner := bufio.NewScanner(os.Stdin)
	var lines []string
	for {
		scanner.Scan()
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// PrintProgressBar displays a progress bar in the terminal.
func PrintProgressBar(progress, total int, width int) {
	percent := float64(progress) / float64(total) * 100.0
	filled := int(float64(width) * (float64(progress) / float64(total)))
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	fmt.Printf("\r[%s] %.2f%%", bar, percent)
	if progress == total {
		fmt.Println()
	}
}
