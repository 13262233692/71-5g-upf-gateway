//go:build !linux
// +build !linux

package bpf

import (
	"errors"
	"net"
)

type Manager struct{}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) LoadBPFProgram() error {
	return errors.New("BPF not supported on this platform")
}

func (m *Manager) AttachXDP(ifaceName string) error {
	return errors.New("XDP not supported on this platform")
}

func (m *Manager) DetachXDP() error {
	return nil
}

func (m *Manager) AddPDR(teid uint32, dstMAC net.HardwareAddr, ifIndex uint32, qfi uint8, action uint8) error {
	return errors.New("BPF maps not supported on this platform")
}

func (m *Manager) RemovePDR(teid uint32) error {
	return errors.New("BPF maps not supported on this platform")
}

func (m *Manager) GetPDR(teid uint32) (*PDRValue, error) {
	return nil, errors.New("BPF maps not supported on this platform")
}

func (m *Manager) AddForwardEntry(ifIndex uint32, targetIfIndex uint32) error {
	return errors.New("BPF maps not supported on this platform")
}

func (m *Manager) RemoveForwardEntry(ifIndex uint32) error {
	return errors.New("BPF maps not supported on this platform")
}

func (m *Manager) GetStats() (*Stats, error) {
	return nil, errors.New("BPF maps not supported on this platform")
}

func (m *Manager) ListPDRs() (map[uint32]PDRValue, error) {
	return nil, errors.New("BPF maps not supported on this platform")
}

func (m *Manager) SetInterfaceUp(ifaceName string) error {
	return errors.New("netlink not supported on this platform")
}

func (m *Manager) Close() error {
	return nil
}
