package server

import (
	"encoding/json"
	"fmt"
	"log"
	"prac/pkg/crypto"
	"prac/pkg/store"
	"time"

	"github.com/google/uuid"
	"go.etcd.io/bbolt"
)

func (s *serverImpl) vaciabd(bs *store.BboltStore) {
	// Elimina los buckets de encuestas
	err := bs.DB.Update(func(tx *bbolt.Tx) error {
		// Elimina el bucket de encuestas
		if err := tx.DeleteBucket(store.BucketName("polls")); err != nil && err != bbolt.ErrBucketNotFound {
			return fmt.Errorf("error al eliminar bucket polls: %v", err)
		}

		// Elimina el bucket de votos de usuarios
		if err := tx.DeleteBucket(store.BucketName("user_votes")); err != nil && err != bbolt.ErrBucketNotFound {
			return fmt.Errorf("error al eliminar bucket user_votes: %v", err)
		}

		fmt.Println("Buckets de encuestas eliminados correctamente")
		return nil
	})
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func (s *serverImpl) seedPolls() {
	fmt.Println("🏁 Ejecutando seed de encuestas...")

	samplePolls := []Poll{
		// programadores
		{
			Title:      "Mejor lenguaje de programacion",
			Options:    []string{"Go", "Python", "C++", "JavaScript"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: false,
			UserGroup:  "programadores",
		},
		{
			Title:      "Editor de codigo favorito",
			Options:    []string{"VSCode", "Vim", "Emacs", "Sublime Text", "GoLand"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "programadores",
		},
		{
			Title:      "Framework web preferido",
			Options:    []string{"Gin", "Echo", "Fiber", "Revel"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: false,
			UserGroup:  "programadores",
		},
		{
			Title:      "Lenguaje de scripting favorito",
			Options:    []string{"Bash", "Python", "Ruby", "Perl"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "programadores",
		},
		{
			Title:      "Sistema de control de versiones",
			Options:    []string{"Git", "Mercurial", "SVN", "Perforce"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "programadores",
		},

		//estudiantes
		{
			Title:      "Nota que se merece este trabajo",
			Options:    []string{"Un 10", "Un 5 x 2", "Diez veces 1", "Venga va, os pongo un 10"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "estudiantes",
		},
		{
			Title:      "Paella o pizza para almuerzo",
			Options:    []string{"Paella", "Pizza"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "estudiantes",
		},
		{
			Title:      "Materia preferida",
			Options:    []string{"Matematicas", "Historia", "Fisica", "Literatura"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: false,
			UserGroup:  "estudiantes",
		},
		{
			Title:      "Metodo de estudio",
			Options:    []string{"Apuntes", "Flashcards", "Grupos de estudio", "Resumir"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: false,
			UserGroup:  "estudiantes",
		},
		{
			Title:      "Hora de mayor productividad",
			Options:    []string{"Manana", "Tarde", "Noche", "Madrugada"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "estudiantes",
		},

		// deportistas
		{
			Title:      "Deporte favorito",
			Options:    []string{"Parkour", "Tenis", "Baloncesto", "Surf", "Escalada", "Zapping", "Ping Pong", "Motociclismo", "Esgrima"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: false,
			UserGroup:  "deportistas",
		},
		{
			Title:      "Entrenamiento favorito",
			Options:    []string{"Cardio", "Pesas", "Natacion", "Ciclismo"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: false,
			UserGroup:  "deportistas",
		},
		{
			Title:      "Mejor equipo de futbol",
			Options:    []string{"FC Barcelona", "Real Madrid", "Atletico", "Valencia"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "deportistas",
		},
		{
			Title:      "Bebida post entreno",
			Options:    []string{"Agua", "Batido", "Isotonica", "Cafe"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "deportistas",
		},
		{
			Title:      "Calentamiento ideal",
			Options:    []string{"Estiramientos", "Trote suave", "Saltar cuerda", "Movilidad articular"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: false,
			UserGroup:  "deportistas",
		},

		// oradores
		{
			Title:      "Mociones favoritas de debate",
			Options:    []string{"Politicas", "Cientificas", "De actor", "Tecnicas", "De historia", "De lamentacion", "De bar"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "oradores",
		},

		{
			Title:      "Formato de debate preferido",
			Options:    []string{"Britanico", "Académico", "Lincoln Douglas", "Karl Popper", "Oxford"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "oradores",
		},
		{
			Title:      "Tema de debate favorito",
			Options:    []string{"Politica", "Derechos humanos", "Ciencias", "Medio ambiente"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: false,
			UserGroup:  "oradores",
		},
		{
			Title:      "Tiempo ideal de intervencion",
			Options:    []string{"1 min", "2 min", "3 min", "5 min"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "oradores",
		},
		{
			Title:      "Figura retorica favorita",
			Options:    []string{"Metafora", "Antitesis", "Hiperbole", "Ironia"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "oradores",
		},

		// generales
		{
			Title:      "Mejor tortilla de patatas",
			Options:    []string{"Con cebolla", "Sin cebolla"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "",
		},
		{
			Title:      "Color de fondo preferido",
			Options:    []string{"Azul", "Verde", "Rojo", "Amarillo"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "",
		},
		{
			Title:      "Comida para llevar",
			Options:    []string{"Sushi", "Burgers", "Ensalada", "Tacos"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: false,
			UserGroup:  "",
		},
		{
			Title:      "Estacion del ano favorita",
			Options:    []string{"Verano", "Otono", "Invierno", "Primavera"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "",
		},
		{
			Title:      "Mascota ideal",
			Options:    []string{"Perro", "Gato", "Pez", "Pajaro"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
			UserGroup:  "",
		},
	}

	for _, poll := range samplePolls {
		// Generar UUID y encriptarlo
		pollUUID := uuid.New().String()
		encryptedID, err := crypto.EncryptUUID(pollUUID)
		if err != nil {
			fmt.Println("❌ Error al cifrar ID:", err)
			continue
		}
		poll.ID = encryptedID

		// Inicializar mapa de votos
		poll.Votes = make(map[string]int)
		for _, option := range poll.Options {
			poll.Votes[option] = 0
		}

		// Serializar y guardar
		pollBytes, err := json.Marshal(poll)
		if err != nil {
			fmt.Println("❌ Error al serializar encuesta:", err)
			continue
		}

		key := store.HashBytes([]byte(pollUUID))
		err = s.db.Put(bucketPolls, key, pollBytes)
		if err != nil {
			fmt.Println("❌ Error al guardar encuesta:", err)
			continue
		}

		fmt.Printf("✅ Encuesta \"%s\" guardada\n", poll.Title)
	}

	fmt.Println("✅ Seeding completo.")
}
