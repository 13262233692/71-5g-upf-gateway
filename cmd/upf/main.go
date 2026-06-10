package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/5g-upf/upf-gateway/internal/config"
	"github.com/5g-upf/upf-gateway/pkg/upf"
)

func main() {
	cfg := config.Load()

	upfConfig := upf.Config{
		N3Interface:   cfg.N3Interface,
		N6Interface:   cfg.N6Interface,
		N3Address:     cfg.N3Address,
		N6Address:     cfg.N6Address,
		NodeID:        cfg.NodeID,
		LogLevel:      cfg.LogLevel,
		StatsInterval: cfg.StatsInterval,
	}

	service := upf.NewService(upfConfig)

	fmt.Println("========================================")
	fmt.Println("5G UPF Gateway with XDP/eBPF")
	fmt.Println("========================================")
	fmt.Printf("Node ID:         %s\n", cfg.NodeID)
	fmt.Printf("N3 Interface:    %s (%s)\n", cfg.N3Interface, cfg.N3Address)
	fmt.Printf("N6 Interface:    %s (%s)\n", cfg.N6Interface, cfg.N6Address)
	fmt.Printf("Stats Interval:  %s\n", cfg.StatsInterval)
	fmt.Println("========================================")

	if err := service.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start UPF service: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("UPF service started successfully")

	demoData(service)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("UPF gateway is running. Press Ctrl+C to stop...")
	<-sigCh

	fmt.Println("\nShutting down UPF gateway...")
	if err := service.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping UPF service: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("UPF gateway stopped gracefully")
}

func demoData(service *upf.Service) {
	fmt.Println("\nLoading demo session data...")

	demoMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	demoMAC2, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	sessions := []*upf.Session{
		{
			SEID:   1001,
			UEIP:   net.ParseIP("10.45.0.10"),
			UPFIP:  net.ParseIP("192.168.1.1"),
			TEIDUL: 0x00000001,
			TEIDDL: 0x00000002,
			UEMAC:  demoMAC,
			GNBIP:  net.ParseIP("192.168.1.2"),
			GNBMAC: demoMAC2,
			QFI:    9,
			DNN:    "internet",
		},
		{
			SEID:   1002,
			UEIP:   net.ParseIP("10.45.0.11"),
			UPFIP:  net.ParseIP("192.168.1.1"),
			TEIDUL: 0x00000003,
			TEIDDL: 0x00000004,
			UEMAC:  demoMAC,
			GNBIP:  net.ParseIP("192.168.1.2"),
			GNBMAC: demoMAC2,
			QFI:    5,
			DNN:    "internet",
		},
		{
			SEID:   1003,
			UEIP:   net.ParseIP("10.45.0.12"),
			UPFIP:  net.ParseIP("192.168.1.1"),
			TEIDUL: 0x00000005,
			TEIDDL: 0x00000006,
			UEMAC:  demoMAC,
			GNBIP:  net.ParseIP("192.168.1.3"),
			GNBMAC: demoMAC2,
			QFI:    9,
			DNN:    "ims",
		},
	}

	for _, session := range sessions {
		if err := service.CreateSession(session); err != nil {
			fmt.Printf("Warning: failed to create session %d: %v\n", session.SEID, err)
		} else {
			fmt.Printf("Created session: SEID=%d, TEID=0x%08x, QFI=%d, UE=%s\n",
				session.SEID, session.TEIDUL, session.QFI, session.UEIP)
		}
	}

	kernelPDRs, err := service.GetKernelPDRs()
	if err != nil {
		fmt.Printf("Warning: failed to get kernel PDRs: %v\n", err)
	} else {
		fmt.Printf("\nKernel PDR map contains %d entries:\n", len(kernelPDRs))
		for teid, pdr := range kernelPDRs {
			fmt.Printf("  TEID=0x%08x -> DstMAC=%v, IfIndex=%d, QFI=%d, Action=%d\n",
				teid, net.HardwareAddr(pdr.DstMAC[:]), pdr.IfIndex, pdr.QFI, pdr.Action)
		}
	}

	fmt.Println()
}
