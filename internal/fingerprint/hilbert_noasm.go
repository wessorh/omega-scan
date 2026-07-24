//go:build !amd64

package fingerprint

// Stub — non-AVX2 platforms use the scalar fallback in NewCurve.
func hilbertD2XYBatchAVX2(distances *uint32, packed *uint64, count uint64, order uint32) {
	panic("hilbertD2XYBatchAVX2: not implemented on this architecture")
}
