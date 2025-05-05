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
		{
			Title:      "Mejor lenguaje de programación",
			Options:    []string{"Go", "Python", "C++", "JavaScript"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: false,
		},
		{
			Title:      "Nota que se merece este trabajo",
			Options:    []string{"Un 10", "Un 5 x 2", "Diez veces 1", "Venga va, os pongo un 10"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
		},
		{
			Title:      "Mejor tortilla de patatas",
			Options:    []string{"Con cebolla", "Sin cebolla"},
			EndDate:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			SingleVote: true,
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
