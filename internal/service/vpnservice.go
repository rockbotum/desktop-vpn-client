package service

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"SigmaVPN/internal/cryptor"
	"SigmaVPN/internal/middleware/handler"

	"github.com/Doridian/water"
)

type VPNService struct {
	mu        sync.Mutex
	isRunning bool
	cancel    context.CancelFunc
	tun       *water.Interface
	udpConn   *net.UDPConn
	wg        sync.WaitGroup
}

func NewVPNService() *VPNService {
	return &VPNService{}
}

func (s *VPNService) Connect(serverAddress string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isRunning {
		return "Already connected", nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	tun, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		cancel()
		return "", fmt.Errorf("service: создание TUN: %w", err)
	}

	c := cryptor.New()

	serverAddr, err := net.ResolveUDPAddr("udp", serverAddress)
	if err != nil {
		cancel()
		_ = tun.Close()
		return "", fmt.Errorf("service: разрешение адреса %q: %w", serverAddress, err)
	}

	udpConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		cancel()
		_ = tun.Close()
		return "", fmt.Errorf("service: подключение к серверу: %w", err)
	}

	log.Printf("TUN создан: %s, сервер %s", tun.Name(), serverAddr)

	s.cancel = cancel
	s.tun = tun
	s.udpConn = udpConn
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		handler.Send(ctx, udpConn, tun, c)
	}()
	go func() {
		defer s.wg.Done()
		handler.Get(ctx, udpConn, tun, c)
	}()

	s.isRunning = true
	return "Connected", nil
}

func (s *VPNService) Disconnect() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isRunning {
		return "Not connected"
	}

	log.Printf("Завершение работы...")
	if s.cancel != nil {
		s.cancel()
	}
	if s.tun != nil {
		_ = s.tun.Close()
	}
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}
	s.wg.Wait()

	s.isRunning = false
	s.cancel = nil
	s.tun = nil
	s.udpConn = nil
	return "Disconnected"
}

func (s *VPNService) GetStatus() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isRunning {
		return "Connected"
	}
	return "Disconnected"
}
