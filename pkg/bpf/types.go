package bpf

const (
	BPFFSPath = "/sys/fs/bpf"
	MapDir    = BPFFSPath + "/upf"

	PDRActionForward  = 0
	PDRActionDrop     = 1
	PDRActionRedirect = 2

	PDRMagic    = 0x50445255
	PDRRetryMax = 3

	QOSMagic = 0x514F5300

	QFIVoNR   = 1
	QFIVideo  = 2
	QFIIMS    = 5
	QFIEMBMS  = 7
	QFIDefault = 9

	QOSFlowGBR    = 0
	QOSFlowNonGBR = 1

	QOSActionPass = 0
	QOSActionMark = 1
	QOSActionShape = 2
	QOSActionDrop = 3

	MaxQOSFlows = 1024
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

type TokenBucket struct {
	Tokens       uint64
	LastUpdateNs uint64
	RateBps      uint64
	BurstSize    uint64
	Magic        uint32
	Reserved     uint32
}

type QoSFlowKey struct {
	TEID    uint32
	QFI     uint8
	Padding [3]uint8
}

type QoSFlowValue struct {
	Lock         uint32
	Magic        uint32
	QFI          uint8
	FlowType     uint8
	Priority     uint8
	Action       uint8
	GBRBps       uint64
	MBRBps       uint64
	BucketGBR    TokenBucket
	BucketMBR    TokenBucket
	TotalBytes   uint64
	DroppedBytes uint64
	ShapedPackets uint64
}

type Stats struct {
	RxPackets          uint64
	RxBytes            uint64
	TxPackets          uint64
	TxBytes            uint64
	DropPackets        uint64
	GtpuPackets        uint64
	TeidMiss           uint64
	TeidHit            uint64
	TornReadDetected   uint64
	SpinLockContention uint64
	PDRUpdateRetries   uint64
	QoSShapedPackets   uint64
	QoSDroppedGBR      uint64
	QoSDroppedMBR      uint64
	QoSVoNRProtected   uint64
}
