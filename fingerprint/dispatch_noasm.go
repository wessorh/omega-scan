//go:build !amd64

package fingerprint

// zeroBuffer zeroes buf in pure Go (non-amd64 fallback; the AVX2 assembly
// zeroBufferAVX2 is amd64-only).
func zeroBuffer(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
