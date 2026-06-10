package upf

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	bpfpkg "github.com/5g-upf/upf-gateway/pkg/bpf"
)

type Config struct {
	N3Interface     string
	N6Interface     string
	N3Address       string
	N6Address       string
	NodeID          string
	LogLevel        string
	StatsInterval   time.Duration
}

type Service struct {
	config         Config
	bpf            *bpfpkg.Manager
	sessionMgr     *SessionManager
	pdrMgr         *PDRManager
	mu             sync.RWMutex
	running        bool
	ctx            context.Context
	cancel         context.CancelFunc
	statsTicker    *time.Ticker
}

func NewService(cfg Config) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		config:      cfg,
		bpf:         bpfpkg.NewManager(),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("service already running")
	}

	if err := s.bpf.LoadBPFProgram(); err != nil {
		return fmt.Errorf("loading BPF program: %w", err)
	}

	if err := s.bpf.AttachXDP(s.config.N3Interface); err != nil {
		return fmt.Errorf("attaching XDP to %s: %w", s.config.N3Interface, err)
	}

	if err := s.bpf.SetInterfaceUp(s.config.N3Interface); err != nil {
		return fmt.Errorf("setting interface %s up: %w", s.config.N3Interface, err)
	}

	if s.config.N6Interface != "" && s.config.N6Interface != s.config.N3Interface {
		if err := s.bpf.SetInterfaceUp(s.config.N6Interface); err != nil {
			return fmt.Errorf("setting interface %s up: %w", s.config.N6Interface, err)
		}

		n3Iface, err := net.InterfaceByName(s.config.N3Interface)
		if err != nil {
			return fmt.Errorf("getting N3 interface: %w", err)
		}

		n6Iface, err := net.InterfaceByName(s.config.N6Interface)
		if err != nil {
			return fmt.Errorf("getting N6 interface: %w", err)
		}

		if err := s.bpf.AddForwardEntry(uint32(n3Iface.Index), uint32(n6Iface.Index)); err != nil {
			return fmt.Errorf("adding forward entry: %w", err)
		}
	}

	s.sessionMgr = NewSessionManager(s.bpf)
	s.pdrMgr = NewPDRManager(s.bpf)

	if s.config.StatsInterval > 0 {
		s.statsTicker = time.NewTicker(s.config.StatsInterval)
		go s.statsLoop()
	}

	s.running = true
	return nil
}

func (s *Service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.cancel()

	if s.statsTicker != nil {
		s.statsTicker.Stop()
	}

	if err := s.bpf.Close(); err != nil {
		return fmt.Errorf("closing BPF manager: %w", err)
	}

	s.running = false
	return nil
}

func (s *Service) statsLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.statsTicker.C:
			stats, err := s.bpf.GetStats()
			if err != nil {
				continue
			}

			s.logStats(stats)
		}
	}
}

func (s *Service) logStats(stats *bpfpkg.Stats) {
	fmt.Printf("=== UPF Statistics ===\n")
	fmt.Printf("Rx Packets:     %d\n", stats.RxPackets)
	fmt.Printf("Rx Bytes:       %d\n", stats.RxBytes)
	fmt.Printf("Tx Packets:     %d\n", stats.TxPackets)
	fmt.Printf("Tx Bytes:       %d\n", stats.TxBytes)
	fmt.Printf("Drop Packets:   %d\n", stats.DropPackets)
	fmt.Printf("GTP-U Packets:  %d\n", stats.GtpuPackets)
	fmt.Printf("TEID Hit:       %d\n", stats.TeidHit)
	fmt.Printf("TEID Miss:      %d\n", stats.TeidMiss)
	fmt.Printf("Torn Reads:     %d\n", stats.TornReadDetected)
	fmt.Printf("Lock Contention:%d\n", stats.SpinLockContention)
	fmt.Printf("PDR Retries:    %d\n", stats.PDRUpdateRetries)

	if stats.GtpuPackets > 0 {
		hitRate := float64(stats.TeidHit) / float64(stats.GtpuPackets) * 100
		fmt.Printf("TEID Hit Rate:  %.2f%%\n", hitRate)
	}

	if stats.TornReadDetected > 0 {
		tornRate := float64(stats.TornReadDetected) / float64(stats.GtpuPackets) * 100
		fmt.Printf("Torn Read Rate: %.6f%%\n", tornRate)
	}
	fmt.Println("========================")
}

func (s *Service) CreateSession(session *Session) error {
	if !s.running {
		return fmt.Errorf("service not running")
	}
	return s.sessionMgr.CreateSession(session)
}

func (s *Service) RemoveSession(seid uint64) error {
	if !s.running {
		return fmt.Errorf("service not running")
	}
	return s.sessionMgr.RemoveSession(seid)
}

func (s *Service) GetSession(seid uint64) (*Session, error) {
	if !s.running {
		return nil, fmt.Errorf("service not running")
	}
	return s.sessionMgr.GetSession(seid)
}

func (s *Service) ListSessions() []*Session {
	if !s.running {
		return nil
	}
	return s.sessionMgr.ListSessions()
}

func (s *Service) AddPDR(pdr *PDR) error {
	if !s.running {
		return fmt.Errorf("service not running")
	}
	return s.pdrMgr.AddPDR(pdr)
}

func (s *Service) RemovePDR(pdrID uint16) error {
	if !s.running {
		return fmt.Errorf("service not running")
	}
	return s.pdrMgr.RemovePDR(pdrID)
}

func (s *Service) ListPDRs() []*PDR {
	if !s.running {
		return nil
	}
	return s.pdrMgr.ListPDRs()
}

func (s *Service) GetStats() (*bpfpkg.Stats, error) {
	if !s.running {
		return nil, fmt.Errorf("service not running")
	}
	return s.bpf.GetStats()
}

func (s *Service) GetKernelPDRs() (map[uint32]bpfpkg.PDRValue, error) {
	if !s.running {
		return nil, fmt.Errorf("service not running")
	}
	return s.bpf.ListPDRs()
}

func (s *Service) SessionManager() *SessionManager {
	return s.sessionMgr
}

func (s *Service) PDRManager() *PDRManager {
	return s.pdrMgr
}

func (s *Service) BPFManager() *bpfpkg.Manager {
	return s.bpf
}

func (s *Service) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}
