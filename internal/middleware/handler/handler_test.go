package handler_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"SigmaVPN/internal/cryptor"
	"SigmaVPN/internal/middleware/handler"

	"github.com/Doridian/water"
	"golang.org/x/crypto/chacha20poly1305"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func newTestCryptor(t *testing.T) *cryptor.Cryptor {
	t.Helper()
	aead, err := chacha20poly1305.New(testKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}
	return &cryptor.Cryptor{AEAD: aead}
}

// fakeTUN — управляемый дублёр TUN. Чтение блокируется до подачи пакета
// или закрытия; запись сохраняется. Реальный драйвер не нужен.
type fakeTUN struct {
	reads   chan []byte
	closed  chan struct{}
	closeOn sync.Once

	mu      sync.Mutex
	written [][]byte
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{
		reads:  make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func (f *fakeTUN) Read(b []byte) (int, error) {
	select {
	case p := <-f.reads:
		return copy(b, p), nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakeTUN) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written = append(f.written, append([]byte(nil), b...))
	return len(b), nil
}

func (f *fakeTUN) Close() error {
	f.closeOn.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeTUN) push(p []byte) { f.reads <- append([]byte(nil), p...) }
func (f *fakeTUN) writtenPackets() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.written))
	copy(out, f.written)
	return out
}

func asWaterInterface(f *fakeTUN) *water.Interface {
	return &water.Interface{ReadWriteCloser: f}
}

func udpPair(t *testing.T) (server, client *net.UDPConn) {
	t.Helper()
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	client, err = net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		server.Close()
		t.Fatalf("DialUDP: %v", err)
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return server, client
}

func waitClosed(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("горутина не завершилась за 2с")
	}
}

func TestSend_EncryptsAndSendsOverUDP(t *testing.T) {
	c := newTestCryptor(t)
	tun := newFakeTUN()
	server, client := udpPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		handler.Send(ctx, client, asWaterInterface(tun), c)
		close(done)
	}()

	plain := []byte("ip packet A")
	tun.push(plain)

	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}

	cancel()
	waitClosed(t, done)

	nonceSize := c.NonceSize()
	if n <= nonceSize {
		t.Fatalf("пакет слишком короткий: %d", n)
	}
	got, err := c.Open(nil, buf[:nonceSize], buf[nonceSize:n], nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("расшифровано %q, ожидалось %q", got, plain)
	}
}

func TestGet_DecryptsAndWritesToTUN(t *testing.T) {
	c := newTestCryptor(t)
	tun := newFakeTUN()
	server, client := udpPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		handler.Get(ctx, server, asWaterInterface(tun), c)
		close(done)
	}()

	plain := []byte("ip packet B")
	nonce := c.NextNonce()
	ct := c.Seal(nil, nonce, plain, nil)
	wire := append(append([]byte(nil), nonce...), ct...)
	if _, err := client.Write(wire); err != nil {
		t.Fatalf("client.Write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := tun.writtenPackets(); len(got) == 1 {
			if !bytes.Equal(got[0], plain) {
				t.Fatalf("в TUN записано %q, ожидалось %q", got[0], plain)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("пакет не записан в TUN за 2с")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	waitClosed(t, done)
}

func TestSend_ReturnsOnContextCancel(t *testing.T) {
	c := newTestCryptor(t)
	tun := newFakeTUN()
	_, client := udpPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		handler.Send(ctx, client, asWaterInterface(tun), c)
		close(done)
	}()

	cancel()
	waitClosed(t, done)
}

func TestGet_ReturnsOnContextCancel(t *testing.T) {
	c := newTestCryptor(t)
	tun := newFakeTUN()
	server, _ := udpPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		handler.Get(ctx, server, asWaterInterface(tun), c)
		close(done)
	}()

	cancel()
	waitClosed(t, done)
}

func TestSend_ReturnsWhenTUNClosed(t *testing.T) {
	c := newTestCryptor(t)
	tun := newFakeTUN()
	_, client := udpPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // закрывает watcher-горутину внутри Send
	done := make(chan struct{})
	go func() {
		handler.Send(ctx, client, asWaterInterface(tun), c)
		close(done)
	}()

	if err := tun.Close(); err != nil {
		t.Fatalf("tun.Close: %v", err)
	}
	waitClosed(t, done)
}

// Сквозной тест транспорта: пакет из TUN узла A доходит до TUN узла B
// через реальные UDP-сокеты на 127.0.0.1 (без выхода в интернет).
func TestIntegration_PacketTravelsBetweenNodes(t *testing.T) {
	c := newTestCryptor(t)
	tunA := newFakeTUN()
	tunB := newFakeTUN()
	server, clientA := udpPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sendDone := make(chan struct{})
	getDone := make(chan struct{})
	go func() {
		handler.Send(ctx, clientA, asWaterInterface(tunA), c)
		close(sendDone)
	}()
	go func() {
		handler.Get(ctx, server, asWaterInterface(tunB), c)
		close(getDone)
	}()

	plain := []byte("end-to-end packet")
	tunA.push(plain)

	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := tunB.writtenPackets(); len(got) > 0 {
			if !bytes.Equal(got[0], plain) {
				t.Fatalf("узел B получил %q, ожидалось %q", got[0], plain)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("пакет не дошёл от A до B за 2с")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	waitClosed(t, sendDone)
	waitClosed(t, getDone)
}

// Проверка отсутствия утечек горутин после штатного shutdown.
func TestHandlers_NoGoroutineLeakAfterShutdown(t *testing.T) {
	baseline := runtime.NumGoroutine()

	c := newTestCryptor(t)
	tunA := newFakeTUN()
	tunB := newFakeTUN()
	server, clientA := udpPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	sendDone := make(chan struct{})
	getDone := make(chan struct{})
	go func() {
		handler.Send(ctx, clientA, asWaterInterface(tunA), c)
		close(sendDone)
	}()
	go func() {
		handler.Get(ctx, server, asWaterInterface(tunB), c)
		close(getDone)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	waitClosed(t, sendDone)
	waitClosed(t, getDone)

	deadline := time.Now().Add(2 * time.Second)
	for {
		if runtime.NumGoroutine() <= baseline+1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("утечка горутин: baseline=%d, сейчас=%d",
				baseline, runtime.NumGoroutine())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSendEncryptedPacket_FramingAndDecrypt(t *testing.T) {
	c := newTestCryptor(t)
	server, client := udpPair(t)

	plain := []byte("fake ip packet payload")
	if err := handler.SendEncryptedPacket(client, plain, c); err != nil {
		t.Fatalf("SendEncryptedPacket: %v", err)
	}

	buf := make([]byte, 65535)
	n, _, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}
	wire := buf[:n]

	nonceSize := c.NonceSize()
	if n <= nonceSize {
		t.Fatalf("слишком короткий пакет: %d байт", n)
	}
	nonce := wire[:nonceSize]
	cipherText := wire[nonceSize:]

	if !bytes.Equal(nonce, make([]byte, nonceSize)) {
		t.Fatalf("первый nonce должен быть нулевым, получено %x", nonce)
	}
	got, err := c.Open(nil, nonce, cipherText, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("после расшифровки %q, ожидалось %q", got, plain)
	}
}

func TestReceiveAndDecryptPacket_WritesPlaintextToTUN(t *testing.T) {
	c := newTestCryptor(t)
	tun := newFakeTUN()
	plain := []byte("payload from server")

	nonce := c.NextNonce()
	ct := c.Seal(nil, nonce, plain, nil)
	wire := append(append([]byte(nil), nonce...), ct...)

	if err := handler.ReceiveAndDecryptPacket(asWaterInterface(tun), wire, c); err != nil {
		t.Fatalf("ReceiveAndDecryptPacket: %v", err)
	}
	got := tun.writtenPackets()
	if len(got) != 1 {
		t.Fatalf("в TUN записано %d пакетов, ожидался 1", len(got))
	}
	if !bytes.Equal(got[0], plain) {
		t.Fatalf("в TUN записано %q, ожидалось %q", got[0], plain)
	}
}

func TestReceiveAndDecryptPacket_TamperedCiphertextFails(t *testing.T) {
	c := newTestCryptor(t)
	tun := newFakeTUN()
	plain := []byte("payload")

	nonce := c.NextNonce()
	ct := c.Seal(nil, nonce, plain, nil)
	ct[0] ^= 0xff // порча шифротекста
	wire := append(append([]byte(nil), nonce...), ct...)

	if err := handler.ReceiveAndDecryptPacket(asWaterInterface(tun), wire, c); err == nil {
		t.Fatal("ожидалась ошибка аутентификации, получено nil")
	}
	if got := tun.writtenPackets(); len(got) != 0 {
		t.Fatalf("при ошибке расшифровки в TUN не должно быть записи, записано %d", len(got))
	}
}

func TestReceiveAndDecryptPacket_WrongKeyFails(t *testing.T) {
	senderAEAD, err := chacha20poly1305.New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	sender := &cryptor.Cryptor{AEAD: senderAEAD}

	otherAEAD, err := chacha20poly1305.New(bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatal(err)
	}
	receiver := &cryptor.Cryptor{AEAD: otherAEAD}

	tun := newFakeTUN()
	nonce := sender.NextNonce()
	ct := sender.Seal(nil, nonce, []byte("secret"), nil)
	wire := append(append([]byte(nil), nonce...), ct...)

	if err := handler.ReceiveAndDecryptPacket(asWaterInterface(tun), wire, receiver); err == nil {
		t.Fatal("ожидалась ошибка при неверном ключе, получено nil")
	}
}

func TestReceiveAndDecryptPacket_ShortBuffer(t *testing.T) {
	c := newTestCryptor(t)
	tun := newFakeTUN()
	short := make([]byte, c.NonceSize()-1)

	if err := handler.ReceiveAndDecryptPacket(asWaterInterface(tun), short, c); err == nil {
		t.Fatal("ожидалась ошибка для буфера короче nonce, получено nil")
	}
	if got := tun.writtenPackets(); len(got) != 0 {
		t.Fatalf("в TUN не должно быть записи, записано %d", len(got))
	}
}

func TestReceiveAndDecryptPacket_EmptyBuffer(t *testing.T) {
	c := newTestCryptor(t)
	tun := newFakeTUN()

	if err := handler.ReceiveAndDecryptPacket(asWaterInterface(tun), nil, c); err == nil {
		t.Fatal("ожидалась ошибка для пустого буфера, получено nil")
	}
	if got := tun.writtenPackets(); len(got) != 0 {
		t.Fatalf("в TUN не должно быть записи, записано %d", len(got))
	}
}
