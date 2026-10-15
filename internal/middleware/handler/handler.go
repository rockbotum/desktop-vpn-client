package handler

import (
	"SigmaVPN/internal/cryptor"
	"context"
	"log"
	"net"

	"github.com/Doridian/water"
)

func Send(ctx context.Context, udpConn *net.UDPConn, tun *water.Interface, cryptor *cryptor.Cryptor) {
	defer log.Println("sender завершен")
	buf := make([]byte, 65535)

	// Ожидание закрытия
	go func() {
		<-ctx.Done()
		tun.Close() // это разблокирует Read
	}()

	for {
		n, err := tun.Read(buf)
		if err != nil {
			log.Printf("tun.Read: %v", err)
			return
		}
		if err := SendEncryptedPacket(udpConn, buf[:n], cryptor); err != nil {
			log.Printf("send: %v", err)
		}
	}
}

func Get(ctx context.Context, udpConn *net.UDPConn, tun *water.Interface, cryptor *cryptor.Cryptor) {
	defer log.Println("getter завершен")
	buf := make([]byte, 65535)

	// Ожидание закрытия
	go func() {
		<-ctx.Done()
		udpConn.Close() // это разблокирует Read
	}()

	for {
		n, _, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read: %v", err)
			return
		}
		if err := ReceiveAndDecryptPacket(tun, buf[:n], cryptor); err != nil {
			log.Printf("receive: %v", err)
		}
	}
}
