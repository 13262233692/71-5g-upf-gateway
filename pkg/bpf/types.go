package bpf

const (
	BPFFSPath = "/sys/fs/bpf"
	MapDir    = BPFFSPath + "/upf"

	PDRActionForward  = 0
	PDRActionDrop     = 1
	PDRActionRedirect = 2
)

type PDRKey struct {
	TEID uint32
}

type PDRValue struct {
	DstMAC    [6]byte
	IfIndex   uint32
	QFI       uint8
	Action    uint8
	SdfFilter uint32
}

type Stats struct {
	RxPackets   uint64
	RxBytes     uint64
	TxPackets   uint64
	TxBytes     uint64
	DropPackets uint64
	GtpuPackets uint64
	TeidMiss    uint64
	TeidHit     uint64
}
