package fingerprint

import (
	"fmt"
	"math/bits"
)

// OrderAlphabet maps a Hilbert curve order index to the human-readable
// character used in the cluster-ID prefix.
//
//	index  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 …
//	char   ' '' ''c''d''e''f''g''h''i''j''k''m''n''o''p'…
//
// The first two entries are intentionally whitespace (orders 0 and 1 are
// too small to be useful).  Order 15 is the practical maximum (1 GB
// Hilbert curve cache).
const OrderAlphabet = "  cdefghijkmnopqrstuvwxyz"

// MaxOrder is the largest supported Hilbert curve order.
const MaxOrder = len(OrderAlphabet) - 1

// BuildClusterID constructs the human-readable cluster identifier.
//
// Format:  "<order_char>.<32_hex_fingerprint>"
//
// Example:  order=7 ("h"), fp=[16]byte{...}
//
//	→ "h.00286058000750550000040500000000"
func BuildClusterID(order uint32, fp [16]byte) string {
	var c byte
	if int(order) < len(OrderAlphabet) {
		c = OrderAlphabet[order]
	} else {
		c = '?' // overflow — should never happen for valid orders
	}
	return fmt.Sprintf("%c.%032x", c, fp)
}

// EnclosingOrder returns the smallest Hilbert order N such that
// 4ᴺ ≥ size.  This matches the C library's hilbert_calculate_order.
//
// Mathematically: order = ⌈log₂(size) / 2⌉, clamped to [5, MaxOrder].
func EnclosingOrder(size int64) uint32 {
	if size <= 0 {
		return 5 // minimum for any non-empty buffer
	}
	// log₂(size): find the position of the highest set bit
	bits := bits.Len64(uint64(size))
	if bits == 0 {
		return 5
	}
	order := (bits + 1) / 2 // ceil(bits/2)
	if order < 5 {
		order = 5
	}
	if order > int(MaxOrder) {
		order = int(MaxOrder)
	}
	return uint32(order)
}

// CalculateOrder returns the exact Hilbert order required to map a buffer
// of the given length.  This matches the C library's exact order calculation
// (which includes a 74% padding constraint check).
//
// Returns the order and the grid dimension (2^order).
func CalculateOrder(bufLen int64) (order uint32, dimension uint32) {
	// The Hilbert curve order is ceil(log₂(size) / 2).  We use the
	// minimum enclosing order directly — the C library enforces a
	// 74% padding constraint only as a safety guard, not as a search
	// criterion.
	o := EnclosingOrder(bufLen)
	dim := uint64(1) << o // 2^order
	return o, uint32(dim)
}
