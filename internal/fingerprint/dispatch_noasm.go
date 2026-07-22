//go:build !amd64

package fingerprint

func isAVX2Available() bool { return false }

func zeroBuffer(buf []byte) { zeroBufferGo(buf) }
