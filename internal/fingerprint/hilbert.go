package fingerprint

import (
	"fmt"
	"sync"
)

// PackedCoord stores a 2D Hilbert coordinate as a single uint64:
//
//	bits 63:32 — X coordinate
//	bits 31:0  — Y coordinate
type PackedCoord uint64

// PackCoord packs X and Y into a single uint64.
func PackCoord(x, y uint32) PackedCoord {
	return PackedCoord(uint64(x)<<32 | uint64(y))
}

// Unpack extracts X and Y from a packed coordinate.
func (p PackedCoord) Unpack() (x, y uint32) {
	return uint32(uint64(p) >> 32), uint32(uint64(p) & 0xFFFFFFFF)
}

// Curve is a pre-computed Hilbert curve.
type Curve struct {
	Order     uint32        // Hilbert order N
	Dimension uint32        // 2^order — the grid width/height
	Points    []PackedCoord // 4^order packed coordinates, index = distance
}

// NewCurve generates a Hilbert curve of the given order.
//
// The curve maps a 1D distance (0 .. 4^order-1) to a 2D (x, y)
// coordinate on a grid of size 2^order × 2^order.
//
// Memory: 4^order × 8 bytes.  Order 13 = 64 MB, order 14 = 256 MB,
// order 15 = 1 GB.
func NewCurve(order uint32) (*Curve, error) {
	if order > uint32(MaxOrder) {
		return nil, fmt.Errorf("order %d exceeds maximum %d", order, MaxOrder)
	}

	dim := uint32(1) << order
	nPoints := uint64(1) << (2 * order) // 4^order

	c := &Curve{
		Order:     order,
		Dimension: dim,
		Points:    make([]PackedCoord, nPoints),
	}

	// Standard iterative d2xy: for each distance d, compute (x, y)
	// using the bit-flip algorithm.  This matches the scalar fallback
	// in hilbert_avx2.s.
	for d := uint64(0); d < nPoints; d++ {
		x, y := d2xy(order, d)
		c.Points[d] = PackCoord(x, y)
	}

	return c, nil
}

// d2xy converts a Hilbert distance d to an (x, y) coordinate pair on
// a 2^order × 2^order grid.  This is the standard iterative algorithm
// (Lam & Shapiro, 1981).
func d2xy(order uint32, d uint64) (x, y uint32) {
	n := uint32(1) << order
	var rx, ry uint32

	for s := uint32(1); s < n; s <<= 1 {
		// Extract bits: rx = bit 0 of d/2, ry = bit 0 of (d XOR rx)
		rx = uint32((d >> 1) & 1)
		ry = uint32((d ^ uint64(rx)) & 1)
		rot(s, &x, &y, rx, ry)
		x += s * rx
		y += s * ry
		d >>= 2
	}
	return x, y
}

// rot applies the Hilbert curve rotation/reflection step.
func rot(n uint32, x, y *uint32, rx, ry uint32) {
	if ry == 0 {
		if rx == 1 {
			*x = n - 1 - *x
			*y = n - 1 - *y
		}
		// Swap x and y
		*x, *y = *y, *x
	}
}

// ── Global curve cache ──────────────────────────────────────────────────

var (
	curveMu    sync.Mutex
	evenCurve  *Curve // for even-parity orders
	oddCurve   *Curve // for odd-parity orders
	maxCached  uint32
)

// Init initializes the global Hilbert curve cache.  Must be called
// once before any fingerprinting.
//
// The order parameter sets the maximum supported order.  Internally
// two curves are generated: the largest even order ≤ order, and the
// largest odd order ≤ order.  This dual-cache matches the C library
// behaviour.
func Init(order uint32) error {
	if order > uint32(MaxOrder) {
		order = uint32(MaxOrder)
	}

	evenOrder := order
	if evenOrder%2 == 1 {
		evenOrder--
	}
	oddOrder := order
	if oddOrder%2 == 0 {
		oddOrder--
	}
	if evenOrder < 5 {
		evenOrder = 4
	}
	if oddOrder < 5 {
		oddOrder = 5
	}

	curveMu.Lock()
	defer curveMu.Unlock()

	if maxCached >= order {
		return nil // already initialized at this level or higher
	}

	c, err := NewCurve(evenOrder)
	if err != nil {
		return err
	}
	evenCurve = c

	c, err = NewCurve(oddOrder)
	if err != nil {
		evenCurve = nil
		return err
	}
	oddCurve = c

	maxCached = order
	return nil
}

// Cleanup frees the global curve cache.
func Cleanup() {
	curveMu.Lock()
	defer curveMu.Unlock()
	evenCurve = nil
	oddCurve = nil
	maxCached = 0
}

// getCurve returns the appropriate cached curve for the given order.
func getCurve(order uint32) *Curve {
	curveMu.Lock()
	defer curveMu.Unlock()
	if order%2 == 0 {
		return evenCurve
	}
	return oddCurve
}
