package upf

import (
	"fmt"
	"sync"

	bpfpkg "github.com/5g-upf/upf-gateway/pkg/bpf"
	"github.com/5g-upf/upf-gateway/pkg/pfcp"
)

type QoSFlow struct {
	TEID      uint32
	QFI       uint8
	FlowType  uint8
	Priority  uint8
	GBRBps    uint64
	MBRBps    uint64
	BurstBytes uint64
	PDRID     uint16
	QERID     uint32
}

type QoSManager struct {
	mu    sync.RWMutex
	flows map[string]*QoSFlow
	bpf   *bpfpkg.Manager
}

func NewQoSManager(bpf *bpfpkg.Manager) *QoSManager {
	return &QoSManager{
		flows: make(map[string]*QoSFlow),
		bpf:   bpf,
	}
}

func flowKey(teid uint32, qfi uint8) string {
	return fmt.Sprintf("%d:%d", teid, qfi)
}

func (qm *QoSManager) AddFlow(flow *QoSFlow) error {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	key := flowKey(flow.TEID, flow.QFI)
	if _, exists := qm.flows[key]; exists {
		return fmt.Errorf("QoS flow %s already exists", key)
	}

	err := qm.bpf.AddQoSFlow(
		flow.TEID,
		flow.QFI,
		flow.FlowType,
		flow.Priority,
		flow.GBRBps,
		flow.MBRBps,
		flow.BurstBytes,
	)
	if err != nil {
		return fmt.Errorf("adding QoS flow to BPF: %w", err)
	}

	qm.flows[key] = flow
	return nil
}

func (qm *QoSManager) RemoveFlow(teid uint32, qfi uint8) error {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	key := flowKey(teid, qfi)
	if _, exists := qm.flows[key]; !exists {
		return fmt.Errorf("QoS flow %s not found", key)
	}

	if err := qm.bpf.RemoveQoSFlow(teid, qfi); err != nil {
		return fmt.Errorf("removing QoS flow from BPF: %w", err)
	}

	delete(qm.flows, key)
	return nil
}

func (qm *QoSManager) GetFlow(teid uint32, qfi uint8) (*QoSFlow, error) {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	key := flowKey(teid, qfi)
	flow, exists := qm.flows[key]
	if !exists {
		return nil, fmt.Errorf("QoS flow %s not found", key)
	}
	return flow, nil
}

func (qm *QoSManager) UpdateRates(teid uint32, qfi uint8, gbrBps uint64, mbrBps uint64) error {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	key := flowKey(teid, qfi)
	flow, exists := qm.flows[key]
	if !exists {
		return fmt.Errorf("QoS flow %s not found", key)
	}

	flow.GBRBps = gbrBps
	flow.MBRBps = mbrBps

	if err := qm.bpf.UpdateQoSFlowRates(teid, qfi, gbrBps, mbrBps); err != nil {
		return fmt.Errorf("updating QoS flow rates in BPF: %w", err)
	}

	return nil
}

func (qm *QoSManager) ListFlows() []*QoSFlow {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	flows := make([]*QoSFlow, 0, len(qm.flows))
	for _, flow := range qm.flows {
		flows = append(flows, flow)
	}
	return flows
}

func (qm *QoSManager) FlowCount() int {
	qm.mu.RLock()
	defer qm.mu.RUnlock()
	return len(qm.flows)
}

func QFIToPriority(qfi uint8) uint8 {
	switch qfi {
	case bpfpkg.QFIVoNR:
		return 1
	case bpfpkg.QFIVideo:
		return 3
	case bpfpkg.QFIIMS:
		return 5
	case bpfpkg.QFIEMBMS:
		return 4
	case bpfpkg.QFIDefault:
		return 7
	default:
		return 7
	}
}

func ClassifyFlowType(qfi uint8) uint8 {
	switch qfi {
	case bpfpkg.QFIVoNR, bpfpkg.QFIVideo:
		return bpfpkg.QOSFlowGBR
	default:
		return bpfpkg.QOSFlowNonGBR
	}
}

func DefaultBurstBytes(rateBps uint64) uint64 {
	burstMs := uint64(10)
	return rateBps * burstMs / 8000
}

func (qm *QoSManager) ApplyPFCPModification(mod *pfcp.SessionMod) error {
	for _, qer := range mod.QERs {
		if qer.QFI == 0 {
			continue
		}

		var teid uint32
		for _, pdr := range mod.PDRs {
			if pdr.QFI == qer.QFI || pdr.PDRID > 0 {
				teid = pdr.TEID
				break
			}
		}

		if teid == 0 {
			continue
		}

		mbrBps := qer.MBRDL
		gbrBps := qer.GBRDL
		if mbrBps == 0 {
			mbrBps = gbrBps * 2
		}

		priority := QFIToPriority(qer.QFI)
		flowType := ClassifyFlowType(qer.QFI)
		burstBytes := DefaultBurstBytes(mbrBps)

		flow := &QoSFlow{
			TEID:       teid,
			QFI:        qer.QFI,
			FlowType:   flowType,
			Priority:   priority,
			GBRBps:     gbrBps,
			MBRBps:     mbrBps,
			BurstBytes: burstBytes,
		}

		key := flowKey(teid, qer.QFI)
		qm.mu.RLock()
		_, exists := qm.flows[key]
		qm.mu.RUnlock()

		if exists {
			if err := qm.UpdateRates(teid, qer.QFI, gbrBps, mbrBps); err != nil {
				return fmt.Errorf("updating QoS flow from PFCP: %w", err)
			}
		} else {
			if err := qm.AddFlow(flow); err != nil {
				return fmt.Errorf("adding QoS flow from PFCP: %w", err)
			}
		}
	}

	return nil
}
