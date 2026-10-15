package cryptor_test

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	"SigmaVPN/internal/cryptor"

	"golang.org/x/crypto/chacha20poly1305"
)

// testKey — фиксированный тестовый ключ. Не является реальным секретом.
func testKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func newTestCryptor(t *testing.T) *cryptor.Cryptor {
	t.Helper()
	aead, err := chacha20poly1305.New(testKey())
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}
	return &cryptor.Cryptor{AEAD: aead}
}

func TestNextNonce_LengthMatchesAEAD(t *testing.T) {
	c := newTestCryptor(t)
	nonce := c.NextNonce()
	if got, want := len(nonce), c.NonceSize(); got != want {
		t.Fatalf("длина nonce = %d, ожидалось %d", got, want)
	}
	if c.NonceSize() != chacha20poly1305.NonceSize {
		t.Fatalf("NonceSize = %d, ожидалось %d", c.NonceSize(), chacha20poly1305.NonceSize)
	}
}

func TestNextNonce_MonotonicAndEncodedBigEndian(t *testing.T) {
	c := newTestCryptor(t)
	for i := uint64(0); i < 5; i++ {
		nonce := c.NextNonce()
		if got := binary.BigEndian.Uint64(nonce); got != i {
			t.Fatalf("итерация %d: counter в nonce = %d", i, got)
		}
		// Хвост nonce должен оставаться нулевым (заполняем только первые 8 байт).
		if !bytes.Equal(nonce[8:], make([]byte, len(nonce)-8)) {
			t.Fatalf("итерация %d: хвост nonce не нулевой: %x", i, nonce[8:])
		}
	}
}

func TestNextNonce_ConcurrentUniqueness(t *testing.T) {
	c := newTestCryptor(t)
	const goroutines = 50
	const perGoroutine = 200

	var (
		mu     sync.Mutex
		nonces = make(map[string]struct{}, goroutines*perGoroutine)
		wg     sync.WaitGroup
	)
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				n := c.NextNonce()
				mu.Lock()
				nonces[string(n)] = struct{}{}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if got, want := len(nonces), goroutines*perGoroutine; got != want {
		t.Fatalf("уникальных nonce = %d, ожидалось %d (гонка/переиспользование)", got, want)
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	c := newTestCryptor(t)
	plain := []byte("hello sigma vpn")
	nonce := c.NextNonce()

	ct := c.Seal(nil, nonce, plain, nil)
	if bytes.Contains(ct, plain) {
		t.Fatal("шифротекст содержит открытый текст")
	}
	got, err := c.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("Open вернул %q, ожидалось %q", got, plain)
	}
}

func TestNew_AEADInitializedAndUsable(t *testing.T) {
	c := cryptor.New()
	if c.AEAD == nil {
		t.Fatal("New() вернул Cryptor с nil AEAD")
	}
	if got := c.NonceSize(); got != chacha20poly1305.NonceSize {
		t.Fatalf("NonceSize = %d, ожидалось %d", got, chacha20poly1305.NonceSize)
	}

	plain := []byte("payload")
	nonce := c.NextNonce()
	got, err := c.Open(nil, nonce, c.Seal(nil, nonce, plain, nil), nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip вернул %q, ожидалось %q", got, plain)
	}
}

func TestNew_GeneratesDistinctKeys(t *testing.T) {
	a, b := cryptor.New(), cryptor.New()
	plain := []byte("payload")
	nonce := a.NextNonce()
	ct := a.Seal(nil, nonce, plain, nil)
	if _, err := b.Open(nil, nonce, ct, nil); err == nil {
		t.Fatal("два экземпляра New() используют одинаковый ключ")
	}
}

func TestNewWithKey_RejectsWrongKeySize(t *testing.T) {
	if _, err := cryptor.NewWithKey([]byte("too-short")); err == nil {
		t.Fatal("ожидалась ошибка для ключа неверной длины")
	}
	key := make([]byte, cryptor.KeySize)
	c, err := cryptor.NewWithKey(key)
	if err != nil {
		t.Fatalf("NewWithKey: %v", err)
	}
	if c.NonceSize() != chacha20poly1305.NonceSize {
		t.Fatalf("NonceSize = %d, ожидалось %d", c.NonceSize(), chacha20poly1305.NonceSize)
	}
}
