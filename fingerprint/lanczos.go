package fingerprint

import (
	"math"
	"sort"
)

// ── Constants (must match C exactly) ──────────────────────────────────

const (
	// Bits is the number of fractional bits in the fixed-point representation.
	Bits = 14

	// ScaleFactor is 2^Bits — the multiplier to convert float → fixed-point.
	ScaleFactor = 1 << Bits // 16384

	// RoundOffset is ScaleFactor/2 — added before the right-shift during
	// accumulation to implement round-to-nearest.
	RoundOffset = 1 << (Bits - 1) // 8192
)

// ── Clamp helpers ─────────────────────────────────────────────────────

func u8(x int) uint8 {
	if x < 0 {
		return 0
	}
	if x > 255 {
		return 255
	}
	return uint8(x)
}

func clip(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ── Lanczos-3 kernel ──────────────────────────────────────────────────

// lanczos3 evaluates the Lanczos-3 windowed sinc function at x.
// Matches the C lanczos3() exactly.
func lanczos3(x float64) float64 {
	const alpha = 3.0

	if x > alpha {
		return 0.0
	}
	if x == 0.0 {
		return 1.0
	}

	b := x * math.Pi
	c := b / alpha
	return math.Sin(b) * math.Sin(c) / (b * c)
}

// ── Double-precision kernel generation ─────────────────────────────────

// makeDoubleKernel computes the floating-point Lanczos-3 kernel weights,
// per-pixel weight sums, per-row starting offsets, and the filter tap count.
//
// Matches make_double_kernel() in lanczos_avx2_optimized.c.
func makeDoubleKernel(inputSize, outputSize int) (
	weights []float64, sums []float64, offsets []int16, taps int,
) {
	scale := float64(outputSize) / float64(inputSize)
	step := scale
	if scale > 1.0 {
		step = 1.0
	}
	support := 3.0 / step
	taps = int(math.Ceil(support)) * 2
	if taps > inputSize {
		taps = inputSize &^ 1 // round down to even
	}

	weights = make([]float64, outputSize*taps)
	sums = make([]float64, outputSize)
	offsets = make([]int16, outputSize)

	xstep := 1.0 / scale
	xmid := float64(inputSize-outputSize) / float64(outputSize*2)

	for i := 0; i < outputSize; i++ {
		left := int(math.Ceil(xmid)) - taps/2
		x := clip(left, 0, inputSize-taps)
		if inputSize-taps < 0 {
			x = 0
		}
		offsets[i] = int16(x)

		var sum float64
		w := weights[i*taps : (i+1)*taps]

		for j := 0; j < taps; j++ {
			w[j] = 0.0
		}

		for j := 0; j < taps; j++ {
			src := left + j
			weight := lanczos3(math.Abs(xmid-float64(src)) * step)
			srcClamped := clip(src, x, inputSize-1) - x
			w[srcClamped] += weight
			sum += weight
		}

		sums[i] = sum
		xmid += xstep
	}

	return weights, sums, offsets, taps
}

// ── Integer (fixed-point) kernel generation ────────────────────────────

// weightEntry is used for sorting kernel weights by absolute magnitude.
type weightEntry struct {
	weight float64
	offset int
}

// makeIntegerKernel converts floating-point Lanczos weights to 14-bit
// signed fixed-point int32 coefficients using error-diffusion rounding.
//
// Matches make_integer_kernel() in lanczos_avx2_optimized.c exactly,
// including the sort-by-absolute-weight ordering.
func makeIntegerKernel(
	taps int, size int,
	weights []float64, sums []float64,
) []int32 {
	coeffs := make([]int32, size*taps)
	sorted := make([]weightEntry, taps)

	for i := 0; i < size; i++ {
		w := weights[i*taps : (i+1)*taps]
		c := coeffs[i*taps : (i+1)*taps]
		sum := sums[i]

		for j := 0; j < taps; j++ {
			sorted[j] = weightEntry{w[j], j}
		}

		// Sort by absolute weight descending (matches C qsort).
		sort.SliceStable(sorted, func(a, b int) bool {
			return math.Abs(sorted[a].weight) > math.Abs(sorted[b].weight)
		})

		diff := 0.0
		scale := float64(ScaleFactor) / sum

		for j := 0; j < taps; j++ {
			weightVal := sorted[j].weight*scale + diff
			iw := math.Floor(weightVal + 0.5)
			c[sorted[j].offset] = int32(iw)
			diff = weightVal - iw
		}
	}

	return coeffs
}

// ── Rotation ───────────────────────────────────────────────────────────

// rotateMatrix90Clockwise rotates a 4×4 matrix 90 degrees clockwise.
// This matches the C rotate_matrix_90_clockwise exactly.
//
// Permutation: {12, 8, 4, 0, 13, 9, 5, 1, 14, 10, 6, 2, 15, 11, 7, 3}
func rotateMatrix90Clockwise(src, dst *[16]byte) {
	perm := [16]int{12, 8, 4, 0, 13, 9, 5, 1, 14, 10, 6, 2, 15, 11, 7, 3}
	for i, p := range perm {
		dst[i] = src[p]
	}
}
