package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

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

func ReadInput(prompt string) string {
	fmt.Print(prompt + ": ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func ReadPassword(prompt string) string {
	fmt.Print(prompt + ": ")
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
		if buf[0] == '\r' || buf[0] == '\n' {
			break
		}
		if buf[0] == 8 || buf[0] == 127 {
			if len(password) > 0 {
				password = password[:len(password)-1]
				fmt.Print("\b \b")
			}
			continue
		}
		password = append(password, rune(buf[0]))
		fmt.Print("*")
	}
	fmt.Println()
	return string(password)
}

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

func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

func Pause(prompt string) {
	fmt.Println(prompt)
	bufio.NewScanner(os.Stdin).Scan()
}

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

func PrintProgressBar(progress, total int, width int) {
	percent := float64(progress) / float64(total) * 100.0
	filled := int(float64(width) * (float64(progress) / float64(total)))
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	fmt.Printf("\r[%s] %.2f%%", bar, percent)
	if progress == total {
		fmt.Println()
	}
}
