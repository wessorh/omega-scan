//go:build amd64

package fingerprint

import "unsafe"

// On amd64, hScaleAVX2 and vScaleAVX2 delegate to the pure-Go fallback.
// The fallback is bit-exact with the holloman5 C library.
// Hand-tuned AVX2 Plan 9 assembly is deferred to a future optimization pass.
//
// The zero buffer (zeroBufferAVX2 in zero_amd64.s) IS implemented in assembly
// and provides a measurable speedup for large Hilbert curve grids.

func hScaleAVX2(dst, src unsafe.Pointer,
	coeffs, offsets unsafe.Pointer,
	taps, width, height, dstPitch, srcPitch int,
) {
	// Convert unsafe.Pointers to slices and delegate to pure Go.
	dstSlice := unsafe.Slice((*byte)(dst), height*dstPitch)
	srcSlice := unsafe.Slice((*byte)(src), height*srcPitch)
	coeffSlice := unsafe.Slice((*int16)(coeffs), width*taps)
	offsetSlice := unsafe.Slice((*int16)(offsets), width)
	hScaleGo(dstSlice, srcSlice, coeffSlice, offsetSlice,
		taps, width, height, dstPitch, srcPitch)
}

func vScaleAVX2(dst, src unsafe.Pointer,
	coeffs, offsets unsafe.Pointer,
	taps, width, height, dstPitch, srcPitch int,
) {
	dstSlice := unsafe.Slice((*byte)(dst), height*dstPitch)
	srcSlice := unsafe.Slice((*byte)(src), height*srcPitch)
	coeffSlice := unsafe.Slice((*int16)(coeffs), height*taps)
	offsetSlice := unsafe.Slice((*int16)(offsets), height)
	vScaleGo(dstSlice, srcSlice, coeffSlice, offsetSlice,
		taps, width, height, dstPitch, srcPitch)
}
