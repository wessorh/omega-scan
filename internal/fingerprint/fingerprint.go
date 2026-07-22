package fingerprint

import (
	"errors"
	"fmt"
)

// ── Public API ─────────────────────────────────────────────────────────

// Version returns the fingerprint library version string.
func Version() string {
	return "omega-scan-holloman3 1.0.0 (pure-go)"
}

// FingerprintBuffer computes a 16-byte holloman3 perceptual fingerprint
// from an in-memory byte slice.
//
// The pipeline matches holloman_fingerprint_buffer() in the holloman5 C
// library exactly:
//
//	bytes → Hilbert map (1D→2D) → Lanczos-3 vertical (N×N → N×4)
//	      → Lanczos-3 horizontal (N×4 → 4×4) → rotate 90° → [16]byte
//
// Returns an error if the fingerprint library has not been initialised
// or if the input is too small.
func FingerprintBuffer(data []byte) ([16]byte, error) {
	var fp [16]byte

	if len(data) < 1024 {
		return fp, errors.New("fingerprint: input too small (minimum 1024 bytes)")
	}

	c := getCurve(EnclosingOrder(int64(len(data))))
	if c == nil {
		return fp, errors.New("fingerprint: not initialised — call Init() first")
	}

	// Step 1: Calculate required order and allocate map buffer.
	order, dim := CalculateOrder(int64(len(data)))
	dimInt := int(dim)
	mapSize := dimInt * dimInt
	pointsNeeded := uint64(mapSize) // 4^order

	if c.Order < order {
		return fp, fmt.Errorf("fingerprint: cached curve order %d < required %d", c.Order, order)
	}

	// Step 2: Allocate and zero the map buffer.
	mapBuf := make([]byte, mapSize)
	zeroBufferGo(mapBuf)

	// Step 3: Map source bytes to Hilbert curve positions.
	// Use dim (from CalculateOrder), not c.Dimension (from the cached
	// higher-order curve).  The first 4^order points of a larger Hilbert
	// curve are identical to an order-N curve of that exact size.
	nPoints := uint64(len(c.Points))
	for i := 0; i < len(data) && uint64(i) < pointsNeeded && uint64(i) < nPoints; i++ {
		x, y := c.Points[i].Unpack()
		pos := int(y)*dimInt + int(x)
		if pos < mapSize {
			mapBuf[pos] = data[i]
		}
	}

	// Step 4: Lanczos-3 vertical scale (dim×dim → dim×4).
	intermediate := make([]byte, dimInt*4)

	vWeights, vSums, vOffsets, vTaps := makeDoubleKernel(dimInt, 4)
	vCoeffs := makeIntegerKernel(vTaps, 4, vWeights, vSums)
	vScaleGo(intermediate, mapBuf, vCoeffs, vOffsets, vTaps,
		dimInt, 4, dimInt, dimInt)

	// Step 5: Lanczos-3 horizontal scale (dim×4 → 4×4).
	final := make([]byte, 4*4)

	hWeights, hSums, hOffsets, hTaps := makeDoubleKernel(dimInt, 4)
	hCoeffs := makeIntegerKernel(hTaps, 4, hWeights, hSums)
	hScaleGo(final, intermediate, hCoeffs, hOffsets, hTaps,
		4, 4, 4, dimInt)

	// Step 6: Rotate 90° clockwise.
	var rotated [16]byte
	rotateMatrix90Clockwise((*[16]byte)(final), &rotated)
	copy(fp[:], rotated[:])

	return fp, nil
}
