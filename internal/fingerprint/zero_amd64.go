//go:build amd64

package fingerprint

import "unsafe"

//go:noescape
//go:nosplit
func zeroBufferAVX2(buf unsafe.Pointer, n int)
