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
	stdlog "log"
	"os"
	"time"

	"prac/pkg/client"
	"prac/pkg/logging"
	"prac/pkg/server"
	"prac/pkg/ui"
)

func main() {
	// Logger para main
	logger := stdlog.New(os.Stdout, "[main] ", stdlog.LstdFlags)

	logger.Println("Iniciando servidor...")
	go func() {
		if err := server.Run(); err != nil {
			logger.Fatalf("Error del servidor: %v\n", err)
		}
	}()

	// Damos un pequeño margen para que arranque el servidor
	const totalSteps = 20
	for i := 1; i <= totalSteps; i++ {
		ui.PrintProgressBar(i, totalSteps, 30)
		time.Sleep(100 * time.Millisecond)
	}

	// Ahora registramos también en Google Drive
	logger.Println("Servidor arrancado en HTTPS en :9200")
	logging.Log("Servidor arrancado en HTTPS en :9200")

	logger.Println("Iniciando cliente...")
	client.Run()
}
