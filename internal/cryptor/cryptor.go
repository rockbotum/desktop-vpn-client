package cryptor

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize — размер сессионного ключа ChaCha20-Poly1305.
const KeySize = chacha20poly1305.KeySize

type Cryptor struct {
	cipher.AEAD
	counter uint64
	mu      sync.Mutex
}

// New создаёт Cryptor со случайным сессионным ключом ChaCha20-Poly1305.
func New() *Cryptor {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("cryptor: генерация ключа: %v", err))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(fmt.Sprintf("cryptor: создание AEAD: %v", err))
	}
	return &Cryptor{AEAD: aead}
}

// NewWithKey создаёт Cryptor с заданным ключом (длина KeySize).
func NewWithKey(key []byte) (*Cryptor, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Cryptor{AEAD: aead}, nil
}

func (c *Cryptor) NextNonce() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	nonce := make([]byte, c.NonceSize())
	binary.BigEndian.PutUint64(nonce, c.counter)
	c.counter++
	return nonce
}
