//go:build !amd64

package fingerprint

import "unsafe"

// hilbertD2XY computes a single Hilbert d2xy coordinate. This is the scalar
// fallback used on non-amd64 platforms; it is bit-identical to the Plan 9
// assembly batch converter (hilbertD2XYBatchAVX2) and the C/Python reference.
func hilbertD2XY(d uint32, order uint32) PackedCoord {
	var x, y uint32
	s := uint32(1)
	for i := uint32(0); i < order; i++ {
		rx := (d >> 1) & 1
		ry := (d ^ rx) & 1
		if ry == 0 {
			if rx == 1 {
				x = s - 1 - x
				y = s - 1 - y
			}
			x, y = y, x
		}
		x += s * rx
		y += s * ry
		d >>= 2
		s <<= 1
	}
	return PackCoord(x, y)
}

// hilbertD2XYBatchAVX2 converts `count` distances to packed (x<<32)|y
// coordinates. On non-amd64 this is a scalar loop (the AVX2 assembly is
// amd64-only).
func hilbertD2XYBatchAVX2(distances *uint32, packed *uint64, count uint64, order uint32) {
	dist := unsafe.Slice(distances, int(count))
	pack := unsafe.Slice(packed, int(count))
	for i := range dist {
		pack[i] = uint64(hilbertD2XY(dist[i], order))
	}
}
