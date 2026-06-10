package upf

import (
	"fmt"
	"net"
	"sync"

	bpfpkg "github.com/5g-upf/upf-gateway/pkg/bpf"
)

type Session struct {
	SEID         uint64
	UEIP         net.IP
	UPFIP        net.IP
	TEIDUL       uint32
	TEIDDL       uint32
	UEMAC        net.HardwareAddr
	GNBIP        net.IP
	GNBMAC       net.HardwareAddr
	QFI          uint8
	DNN          string
	SSCMode      uint8
	PDRID        uint16
	FARID        uint16
	QERID        uint16
	URRID        uint16
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[uint64]*Session
	bpf      *bpfpkg.Manager
}

func NewSessionManager(bpf *bpfpkg.Manager) *SessionManager {
	return &SessionManager{
		sessions: make(map[uint64]*Session),
		bpf:      bpf,
	}
}

func (sm *SessionManager) CreateSession(session *Session) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.sessions[session.SEID]; exists {
		return fmt.Errorf("session %d already exists", session.SEID)
	}

	err := sm.bpf.AddPDR(
		session.TEIDUL,
		session.GNBMAC,
		0,
		session.QFI,
		bpfpkg.PDRActionForward,
	)
	if err != nil {
		return fmt.Errorf("adding PDR for TEID %d: %w", session.TEIDUL, err)
	}

	sm.sessions[session.SEID] = session
	return nil
}

func (sm *SessionManager) RemoveSession(seid uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[seid]
	if !exists {
		return fmt.Errorf("session %d not found", seid)
	}

	if err := sm.bpf.RemovePDR(session.TEIDUL); err != nil {
		return fmt.Errorf("removing PDR for TEID %d: %w", session.TEIDUL, err)
	}

	delete(sm.sessions, seid)
	return nil
}

func (sm *SessionManager) GetSession(seid uint64) (*Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[seid]
	if !exists {
		return nil, fmt.Errorf("session %d not found", seid)
	}
	return session, nil
}

func (sm *SessionManager) GetSessionByTEID(teid uint32) (*Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, session := range sm.sessions {
		if session.TEIDUL == teid || session.TEIDDL == teid {
			return session, nil
		}
	}
	return nil, fmt.Errorf("session with TEID %d not found", teid)
}

func (sm *SessionManager) ListSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

func (sm *SessionManager) SessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

func (sm *SessionManager) UpdateSessionQFI(seid uint64, qfi uint8) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[seid]
	if !exists {
		return fmt.Errorf("session %d not found", seid)
	}

	session.QFI = qfi

	err := sm.bpf.AddPDR(
		session.TEIDUL,
		session.GNBMAC,
		0,
		qfi,
		bpfpkg.PDRActionForward,
	)
	if err != nil {
		return fmt.Errorf("updating PDR for TEID %d: %w", session.TEIDUL, err)
	}

	return nil
}

func (sm *SessionManager) SetupRedirect(ifIndex, targetIfIndex uint32) error {
	return sm.bpf.AddForwardEntry(ifIndex, targetIfIndex)
}

func (sm *SessionManager) RemoveRedirect(ifIndex uint32) error {
	return sm.bpf.RemoveForwardEntry(ifIndex)
}

type PDR struct {
	PDRID       uint16
	TEID        uint32
	UEIP        net.IP
	QFI         uint8
	Action      uint8
	DstMAC      net.HardwareAddr
	OutIfIndex  uint32
	SdfFilter   uint32
}

type PDRManager struct {
	mu  sync.RWMutex
	pdrs map[uint16]*PDR
	bpf *bpfpkg.Manager
}

func NewPDRManager(bpf *bpfpkg.Manager) *PDRManager {
	return &PDRManager{
		pdrs: make(map[uint16]*PDR),
		bpf:  bpf,
	}
}

func (pm *PDRManager) AddPDR(pdr *PDR) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.pdrs[pdr.PDRID]; exists {
		return fmt.Errorf("PDR %d already exists", pdr.PDRID)
	}

	err := pm.bpf.AddPDR(
		pdr.TEID,
		pdr.DstMAC,
		pdr.OutIfIndex,
		pdr.QFI,
		pdr.Action,
	)
	if err != nil {
		return fmt.Errorf("adding PDR to BPF map: %w", err)
	}

	pm.pdrs[pdr.PDRID] = pdr
	return nil
}

func (pm *PDRManager) RemovePDR(pdrID uint16) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pdr, exists := pm.pdrs[pdrID]
	if !exists {
		return fmt.Errorf("PDR %d not found", pdrID)
	}

	if err := pm.bpf.RemovePDR(pdr.TEID); err != nil {
		return fmt.Errorf("removing PDR from BPF map: %w", err)
	}

	delete(pm.pdrs, pdrID)
	return nil
}

func (pm *PDRManager) GetPDR(pdrID uint16) (*PDR, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	pdr, exists := pm.pdrs[pdrID]
	if !exists {
		return nil, fmt.Errorf("PDR %d not found", pdrID)
	}
	return pdr, nil
}

func (pm *PDRManager) ListPDRs() []*PDR {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	pdrs := make([]*PDR, 0, len(pm.pdrs))
	for _, pdr := range pm.pdrs {
		pdrs = append(pdrs, pdr)
	}
	return pdrs
}

func (pm *PDRManager) GetStats() (*bpfpkg.Stats, error) {
	return pm.bpf.GetStats()
}

func (pm *PDRManager) GetKernelPDRs() (map[uint32]bpfpkg.PDRValue, error) {
	return pm.bpf.ListPDRs()
}
