//go:build amd64

package fingerprint

//go:noescape
func hilbertD2XYBatchAVX2(distances *uint32, packed *uint64, count uint64, order uint32)
