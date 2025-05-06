package store

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"prac/pkg/crypto"

	"go.etcd.io/bbolt"
	"golang.org/x/crypto/sha3"
)

func HashBytes(data []byte) []byte {
	h := sha3.New256()
	h.Write(data)
	return h.Sum(nil)
}

func shouldHash(namespace string) bool {
	return (namespace != "usernames" && namespace != "messages" && namespace != "cheese_auth_cypher_uuid" && namespace != "polls")
}

func getKey(namespace string, key []byte) []byte {
	if shouldHash(namespace) {
		return HashBytes(key)
	}
	return key
}

type BboltStore struct {
	DB *bbolt.DB
}

func NewBboltStore(path string) (*BboltStore, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening bbolt database: %v", err)
	}
	return &BboltStore{DB: db}, nil
}

func (s *BboltStore) Put(namespace string, key, value []byte) error {
	encryptedValue, err := crypto.EncryptServer(value)
	if err != nil {
		return fmt.Errorf("error encrypting value: %v", err)
	}
	actualKey := getKey(namespace, key)
	bucketName := BucketName(namespace)
	return s.DB.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return fmt.Errorf("error creating/opening bucket '%s': %v", hex.EncodeToString(bucketName), err)
		}
		return b.Put(actualKey, encryptedValue)
	})
}

func (s *BboltStore) Get(namespace string, key []byte) ([]byte, error) {
	actualKey := getKey(namespace, key)
	bucketName := BucketName(namespace)
	var encryptedVal []byte
	err := s.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", hex.EncodeToString(bucketName))
		}
		encryptedVal = b.Get(actualKey)
		if encryptedVal == nil {
			return fmt.Errorf("key not found: %s", hex.EncodeToString(actualKey))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	decryptedVal, err := crypto.DecryptServer(encryptedVal)
	if err != nil {
		return nil, fmt.Errorf("error decrypting value: %v", err)
	}
	return decryptedVal, nil
}

func (s *BboltStore) Delete(namespace string, key []byte) error {
	actualKey := getKey(namespace, key)
	bucketName := BucketName(namespace)
	return s.DB.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", hex.EncodeToString(bucketName))
		}
		return b.Delete(actualKey)
	})
}

func (s *BboltStore) ListKeys(namespace string) ([][]byte, error) {
	bucketName := BucketName(namespace)
	var keys [][]byte
	err := s.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", hex.EncodeToString(bucketName))
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			kCopy := make([]byte, len(k))
			copy(kCopy, k)
			keys = append(keys, kCopy)
		}
		return nil
	})
	return keys, err
}

func (s *BboltStore) KeysByPrefix(namespace string, prefix []byte) ([][]byte, error) {
	bucketName := BucketName(namespace)
	var actualPrefix []byte
	if shouldHash(namespace) {
		actualPrefix = HashBytes(prefix)
	} else {
		actualPrefix = prefix
	}
	var matchedKeys [][]byte
	err := s.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", hex.EncodeToString(bucketName))
		}
		c := b.Cursor()
		for k, _ := c.Seek(actualPrefix); k != nil && bytes.HasPrefix(k, actualPrefix); k, _ = c.Next() {
			kCopy := make([]byte, len(k))
			copy(kCopy, k)
			matchedKeys = append(matchedKeys, kCopy)
		}
		return nil
	})
	return matchedKeys, err
}

func (s *BboltStore) Close() error {
	return s.DB.Close()
}

func (s *BboltStore) Dump() error {
	err := s.DB.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(bucketName []byte, b *bbolt.Bucket) error {
			fmt.Printf("Bucket: %s\n", hex.EncodeToString(bucketName))
			return b.ForEach(func(k, v []byte) error {
				fmt.Printf("  Key: %s, Value: %s\n", hex.EncodeToString(k), string(v))
				return nil
			})
		})
	})
	if err != nil {
		return fmt.Errorf("error dumping database: %v", err)
	}
	return nil
}

func (s *BboltStore) CountEntries() (int, error) {
	count := 0
	err := s.DB.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bbolt.Bucket) error {
			return b.ForEach(func(k, v []byte) error {
				count++
				return nil
			})
		})
	})
	return count, err
}

func BucketName(namespace string) []byte {
	return HashBytes([]byte(namespace))
}
