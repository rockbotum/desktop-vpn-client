package handler

import (
	"fmt"
	"net"

	"SigmaVPN/internal/cryptor"

	"github.com/Doridian/water"
)

func SendEncryptedPacket(udpConn *net.UDPConn, buffer []byte, cryptor *cryptor.Cryptor) error {
	nonce := cryptor.NextNonce()
	cipherText := cryptor.Seal(nil, nonce, buffer, nil)

	out := make([]byte, 0, len(nonce)+len(cipherText))
	out = append(out, nonce...)
	out = append(out, cipherText...)

	_, err := udpConn.Write(out)
	if err != nil {
		return err
	}
	return nil
}

func ReceiveAndDecryptPacket(tun *water.Interface, buffer []byte, cryptor *cryptor.Cryptor) error {
	nonceSize := cryptor.NonceSize()
	if len(buffer) < nonceSize {
		return fmt.Errorf("service: слишком короткий пакет: %d байт, ожидалось минимум %d", len(buffer), nonceSize)
	}
	nonce := buffer[:nonceSize]
	cipherText := buffer[nonceSize:]

	packet, err := cryptor.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return err
	}

	if _, err := tun.Write(packet); err != nil {
		return fmt.Errorf("service: запись в TUN: %w", err)
	}
	return nil
}
