//go:build amd64

package fingerprint

import "unsafe"

// zeroBuffer zeroes buf using the AVX2 assembly implementation. All deployment
// targets support AVX2, so there is no runtime detection or fallback.
func zeroBuffer(buf []byte) {
	zeroBufferAVX2(unsafe.Pointer(&buf[0]), len(buf))
}
