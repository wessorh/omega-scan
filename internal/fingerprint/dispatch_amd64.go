//go:build amd64

package fingerprint

import (
	"unsafe"

	"golang.org/x/sys/cpu"
)

// isAVX2Available returns true if the CPU supports AVX2.
func isAVX2Available() bool {
	return cpu.X86.HasAVX2
}

// zeroBuffer dispatches to the AVX2 assembly implementation when available,
// falling back to pure Go otherwise.
func zeroBuffer(buf []byte) {
	if isAVX2Available() && len(buf) >= 128 {
		zeroBufferAVX2(unsafe.Pointer(&buf[0]), len(buf))
		return
	}
	zeroBufferGo(buf)
}
