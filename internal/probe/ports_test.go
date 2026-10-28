package probe

import (
	"net"
	"strings"
	"testing"
)

// freePort возвращает порт, который прямо сейчас свободен: слушатель
// поднимается и сразу закрывается.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot allocate a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// TestPortsFreeRejectsListener закрывает дефект прежней проверки: она
// считала порт свободным, если connect не прошёл. На занятом порте connect
// как раз ПРОХОДИТ, но при медленном слушателе или SO_REUSEADDR он может не
// успеть, и тогда ядро поднималось без инбаунда, а проба мерила чужой узел.
func TestPortsFreeRejectsListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	defer ln.Close()

	cfg := Defaults()
	cfg.MixedPort = ln.Addr().(*net.TCPAddr).Port
	cfg.ControlPort = freePort(t)

	err = portsFree(cfg)
	if err == nil {
		t.Fatal("portsFree accepted a port with a live listener: probe would measure someone else's node")
	}
	if !strings.Contains(err.Error(), "busy") {
		t.Errorf("error does not say the port is busy: %v", err)
	}
}

// TestPortsFreeAcceptsFreePorts — обратная сторона: на свободных портах
// проверка не должна ругаться. Без неё тест выше проходил бы на константном
// «занято».
func TestPortsFreeAcceptsFreePorts(t *testing.T) {
	cfg := Defaults()
	cfg.MixedPort = freePort(t)
	cfg.ControlPort = freePort(t)

	if err := portsFree(cfg); err != nil {
		t.Fatalf("portsFree rejected free ports: %v", err)
	}
}

// TestPortsFreeReportsControlPort отдельно проверяет второй порт: если
// смотреть только на mixed-port, занятый external-controller пройдёт
// проверку, и проба будет общаться с чужим REST API.
func TestPortsFreeReportsControlPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	defer ln.Close()

	cfg := Defaults()
	cfg.MixedPort = freePort(t)
	cfg.ControlPort = ln.Addr().(*net.TCPAddr).Port

	err = portsFree(cfg)
	if err == nil {
		t.Fatal("portsFree accepted a busy external-controller")
	}
	if !strings.Contains(err.Error(), "external-controller") {
		t.Errorf("error does not name the busy port: %v", err)
	}
}
