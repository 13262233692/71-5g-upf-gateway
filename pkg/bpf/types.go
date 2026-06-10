package bpf

const (
	BPFFSPath = "/sys/fs/bpf"
	MapDir    = BPFFSPath + "/upf"

	PDRActionForward  = 0
	PDRActionDrop     = 1
	PDRActionRedirect = 2

	PDRMagic    = 0x50445255
	PDRRetryMax = 3
)

type PDRKey struct {
	TEID uint32
}

type PDRValue struct {
	Lock      uint32
	Magic     uint32
	Version   uint32
	DstMAC    [6]byte
	IfIndex   uint32
	QFI       uint8
	Action    uint8
	SdfFilter uint32
	Checksum  uint32
	Reserved  uint32
}

type Stats struct {
	RxPackets        uint64
	RxBytes          uint64
	TxPackets        uint64
	TxBytes          uint64
	DropPackets      uint64
	GtpuPackets      uint64
	TeidMiss         uint64
	TeidHit          uint64
	TornReadDetected uint64
	SpinLockContention uint64
	PDRUpdateRetries uint64
}
