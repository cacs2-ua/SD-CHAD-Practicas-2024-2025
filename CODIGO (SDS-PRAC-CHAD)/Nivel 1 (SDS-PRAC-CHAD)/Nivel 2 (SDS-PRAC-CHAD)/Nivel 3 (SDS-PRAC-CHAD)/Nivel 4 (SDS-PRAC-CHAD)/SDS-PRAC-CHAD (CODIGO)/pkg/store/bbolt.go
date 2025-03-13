package store

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"go.etcd.io/bbolt"
	"golang.org/x/crypto/sha3"
)

// hashBytes returns the SHA3-256 hash of the given data.
func hashBytes(data []byte) []byte {
	h := sha3.New256()
	h.Write(data)
	return h.Sum(nil)
}

/*
	Implementation of the Store interface using BoltDB (bbolt version)
*/

// BboltStore holds the instance of the bbolt database.
type BboltStore struct {
	db *bbolt.DB
}

// NewBboltStore opens the bbolt database at the specified path.
func NewBboltStore(path string) (*BboltStore, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening bbolt database: %v", err)
	}
	return &BboltStore{db: db}, nil
}

// Put stores or updates (key, value) within a bucket (namespace).
// Sub-buckets are not supported.
func (s *BboltStore) Put(namespace string, key, value []byte) error {
	hashedNamespace := hashBytes([]byte(namespace))
	hashedKey := hashBytes(key)
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(hashedNamespace)
		if err != nil {
			return fmt.Errorf("error creating/opening bucket '%s': %v", hex.EncodeToString(hashedNamespace), err)
		}
		return b.Put(hashedKey, value)
	})
}

// Get retrieves the value for the given key in the bucket (namespace).
func (s *BboltStore) Get(namespace string, key []byte) ([]byte, error) {
	hashedNamespace := hashBytes([]byte(namespace))
	hashedKey := hashBytes(key)
	var val []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(hashedNamespace)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", hex.EncodeToString(hashedNamespace))
		}
		val = b.Get(hashedKey)
		if val == nil {
			return fmt.Errorf("key not found: %s", hex.EncodeToString(hashedKey))
		}
		return nil
	})
	return val, err
}

// Delete removes the key from the bucket (namespace).
func (s *BboltStore) Delete(namespace string, key []byte) error {
	hashedNamespace := hashBytes([]byte(namespace))
	hashedKey := hashBytes(key)
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(hashedNamespace)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", hex.EncodeToString(hashedNamespace))
		}
		return b.Delete(hashedKey)
	})
}

// ListKeys returns all keys in the bucket (namespace).
func (s *BboltStore) ListKeys(namespace string) ([][]byte, error) {
	hashedNamespace := hashBytes([]byte(namespace))
	var keys [][]byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(hashedNamespace)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", hex.EncodeToString(hashedNamespace))
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

// KeysByPrefix returns keys that start with 'prefix' in the bucket (namespace).
// Note: Because keys are hashed, prefix searches may not be useful.
func (s *BboltStore) KeysByPrefix(namespace string, prefix []byte) ([][]byte, error) {
	hashedNamespace := hashBytes([]byte(namespace))
	hashedPrefix := hashBytes(prefix)
	var matchedKeys [][]byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(hashedNamespace)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", hex.EncodeToString(hashedNamespace))
		}
		c := b.Cursor()
		for k, _ := c.Seek(hashedPrefix); k != nil && bytes.HasPrefix(k, hashedPrefix); k, _ = c.Next() {
			kCopy := make([]byte, len(k))
			copy(kCopy, k)
			matchedKeys = append(matchedKeys, kCopy)
		}
		return nil
	})
	return matchedKeys, err
}

// Close closes the bbolt database.
func (s *BboltStore) Close() error {
	return s.db.Close()
}

// Dump prints the entire contents of the bbolt database for debugging purposes.
func (s *BboltStore) Dump() error {
	err := s.db.View(func(tx *bbolt.Tx) error {
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
