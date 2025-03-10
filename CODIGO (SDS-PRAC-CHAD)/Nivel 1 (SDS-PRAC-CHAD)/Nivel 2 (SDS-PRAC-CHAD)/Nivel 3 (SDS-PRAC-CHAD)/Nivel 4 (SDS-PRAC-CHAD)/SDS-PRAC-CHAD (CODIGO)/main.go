/*
'prac' es una base para el desarrollo de prácticas en clase con Go.

se puede compilar con "go build" en el directorio donde resida main.go

versión: 1.0

curso: 			**rellenar**
asignatura: 	**antes de**
estudiantes: 	**entregar**
*/
package main

import (
	"log"
	"os"
	"time"

	"prac/pkg/client"
	"prac/pkg/server"
	"prac/pkg/ui"
)

func main() {

	// Creamos un logger con prefijo 'main' para identificar
	// los mensajes en la consola.
	log := log.New(os.Stdout, "[main] ", log.LstdFlags)

	// Inicia servidor en goroutine.
	log.Println("Iniciando servidor...")
	go func() {
		if err := server.Run(); err != nil {
			log.Fatalf("Error del servidor: %v\n", err)
		}
	}()

	// Esperamos un tiempo prudencial a que arranque el servidor.
	const totalSteps = 20
	for i := 1; i <= totalSteps; i++ {
		ui.PrintProgressBar(i, totalSteps, 30)
		time.Sleep(100 * time.Millisecond)
	}

	// Inicia cliente.
	log.Println("Iniciando cliente...")
	client.Run()
}
