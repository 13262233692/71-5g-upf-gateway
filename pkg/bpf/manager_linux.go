//go:build linux
// +build linux

package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// NOTE: Run on Linux to generate BPF bindings:
// go generate ./pkg/bpf/...

type Manager struct {
	objs     *upfXdpObjects
	ingress  link.Link
	egress   link.Link
	iface    *net.Interface
	ifIndex  int
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) LoadBPFProgram() error {
	objs := upfXdpObjects{}
	if err := loadUpfXdpObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	m.objs = &objs

	if err := os.MkdirAll(MapDir, 0755); err != nil {
		return fmt.Errorf("creating BPF map dir: %w", err)
	}

	pinMaps := []struct {
		name string
		m    *ebpf.Map
	}{
		{"teid_pdr_map", objs.TeidPdrMap},
		{"upf_stats_map", objs.UpfStatsMap},
		{"upf_forward_map", objs.UpfForwardMap},
	}

	for _, pm := range pinMaps {
		pinPath := filepath.Join(MapDir, pm.name)
		os.Remove(pinPath)
		if err := pm.m.Pin(pinPath); err != nil {
			return fmt.Errorf("pinning map %s: %w", pm.name, err)
		}
	}

	return nil
}

func (m *Manager) AttachXDP(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("getting interface %s: %w", ifaceName, err)
	}
	m.iface = iface
	m.ifIndex = iface.Index

	ingress, err := link.AttachXDP(link.XDPOptions{
		Program:   m.objs.UpfXdpIngress,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		ingress, err = link.AttachXDP(link.XDPOptions{
			Program:   m.objs.UpfXdpIngress,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return fmt.Errorf("attaching XDP ingress: %w", err)
		}
	}
	m.ingress = ingress

	egress, err := link.AttachXDP(link.XDPOptions{
		Program:   m.objs.UpfXdpEgress,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		egress, err = link.AttachXDP(link.XDPOptions{
			Program:   m.objs.UpfXdpEgress,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return fmt.Errorf("attaching XDP egress: %w", err)
		}
	}
	m.egress = egress

	return nil
}

func (m *Manager) DetachXDP() error {
	if m.ingress != nil {
		if err := m.ingress.Close(); err != nil {
			return err
		}
	}
	if m.egress != nil {
		if err := m.egress.Close(); err != nil {
			return err
		}
	}
	return nil
}

func calcPDRChecksum(value *PDRValue) uint32 {
	var sum uint32 = 0

	sum += value.Magic
	sum += value.Version
	for i := 0; i < 6; i++ {
		sum += uint32(value.DstMAC[i]) << (8 * (i % 4))
	}
	sum += value.IfIndex
	sum += uint32(value.QFI)
	sum += uint32(value.Action)
	sum += value.SdfFilter

	return ^sum
}

func (m *Manager) AddPDR(teid uint32, dstMAC net.HardwareAddr, ifIndex uint32, qfi uint8, action uint8) error {
	teidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(teidBytes, teid)
	key := PDRKey{TEID: binary.BigEndian.Uint32(teidBytes)}
	var macArr [6]byte
	copy(macArr[:], dstMAC)

	var existingVersion uint32 = 0
	existing, err := m.GetPDR(teid)
	if err == nil && existing.Magic == PDRMagic {
		existingVersion = existing.Version
	}

	value := PDRValue{
		Lock:      0,
		Magic:     PDRMagic,
		Version:   existingVersion + 1,
		DstMAC:    macArr,
		IfIndex:   ifIndex,
		QFI:       qfi,
		Action:    action,
		SdfFilter: 0,
		Checksum:  0,
		Reserved:  0,
	}
	value.Checksum = calcPDRChecksum(&value)

	return m.objs.TeidPdrMap.Put(key, value)
}

func (m *Manager) RemovePDR(teid uint32) error {
	teidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(teidBytes, teid)
	key := PDRKey{TEID: binary.BigEndian.Uint32(teidBytes)}
	return m.objs.TeidPdrMap.Delete(key)
}

func (m *Manager) GetPDR(teid uint32) (*PDRValue, error) {
	teidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(teidBytes, teid)
	key := PDRKey{TEID: binary.BigEndian.Uint32(teidBytes)}
	var value PDRValue
	err := m.objs.TeidPdrMap.Lookup(key, &value)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (m *Manager) AddForwardEntry(ifIndex uint32, targetIfIndex uint32) error {
	return m.objs.UpfForwardMap.Put(ifIndex, targetIfIndex)
}

func (m *Manager) RemoveForwardEntry(ifIndex uint32) error {
	return m.objs.UpfForwardMap.Delete(ifIndex)
}

func (m *Manager) GetStats() (*Stats, error) {
	var total Stats

	values, err := m.objs.UpfStatsMap.PossibleCPUs()
	if err != nil {
		return nil, err
	}

	for i := uint32(0); i < uint32(values); i++ {
		var cpuStats Stats
		if err := m.objs.UpfStatsMap.Lookup(&i, &cpuStats); err != nil {
			continue
		}
		total.RxPackets += cpuStats.RxPackets
		total.RxBytes += cpuStats.RxBytes
		total.TxPackets += cpuStats.TxPackets
		total.TxBytes += cpuStats.TxBytes
		total.DropPackets += cpuStats.DropPackets
		total.GtpuPackets += cpuStats.GtpuPackets
		total.TeidMiss += cpuStats.TeidMiss
		total.TeidHit += cpuStats.TeidHit
		total.TornReadDetected += cpuStats.TornReadDetected
		total.SpinLockContention += cpuStats.SpinLockContention
		total.PDRUpdateRetries += cpuStats.PDRUpdateRetries
	}

	return &total, nil
}

func (m *Manager) ListPDRs() (map[uint32]PDRValue, error) {
	result := make(map[uint32]PDRValue)
	var key PDRKey
	var value PDRValue

	iter := m.objs.TeidPdrMap.Iterate()
	for iter.Next(&key, &value) {
		teidBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(teidBytes, key.TEID)
		teid := binary.BigEndian.Uint32(teidBytes)
		result[teid] = value
	}

	return result, iter.Err()
}

func (m *Manager) SetInterfaceUp(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func (m *Manager) Close() error {
	if err := m.DetachXDP(); err != nil {
		return err
	}
	if m.objs != nil {
		return m.objs.Close()
	}
	return nil
}
