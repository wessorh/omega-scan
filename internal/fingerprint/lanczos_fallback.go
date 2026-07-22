package fingerprint

// hScaleGo performs a horizontal Lanczos-3 scale (size×4 → 4×4) in pure Go.
//
// This is the fallback for platforms without AVX2.  It produces bit-identical
// output to the Plan 9 assembly version (hScaleAVX2).
func hScaleGo(
	dst []byte, src []byte,
	coeffs []int16, offsets []int16,
	taps int,
	width, height int,
	dstPitch, srcPitch int,
) {
	_ = height // for the horizontal pass, height is the output row count (4)

	for y := 0; y < height; y++ {
		dstRow := dst[y*dstPitch : y*dstPitch+width]
		for x := 0; x < width; x++ {
			coeffRow := coeffs[x*taps : (x+1)*taps]
			srcCol := int(offsets[x])
			var sum int32
			for k := 0; k < taps; k++ {
				pixel := int32(src[y*srcPitch+srcCol+k])
				weight := int32(coeffRow[k])
				sum += pixel * weight
			}
			sum += RoundOffset
			dstRow[x] = u8(int(sum >> Bits))
		}
	}
}

// vScaleGo performs a vertical Lanczos-3 scale (size×size → size×4) in pure Go.
//
// This is the fallback for platforms without AVX2.  It produces bit-identical
// output to the Plan 9 assembly version (vScaleAVX2).
func vScaleGo(
	dst []byte, src []byte,
	coeffs []int16, offsets []int16,
	taps int,
	width, height int,
	dstPitch, srcPitch int,
) {
	// height = output rows (4 for the vertical pass producing 4 rows)
	// width = number of columns (= srcSize for the full-width output)

	for y := 0; y < height; y++ {
		coeffRow := coeffs[y*taps : (y+1)*taps]
		srcRow0 := int(offsets[y])
		dstRow := dst[y*dstPitch : y*dstPitch+width]
		for x := 0; x < width; x++ {
			var sum int32
			for k := 0; k < taps; k++ {
				pixel := int32(src[(srcRow0+k)*srcPitch+x])
				weight := int32(coeffRow[k])
				sum += pixel * weight
			}
			sum += RoundOffset
			dstRow[x] = u8(int(sum >> Bits))
		}
	}
}

// zeroBufferGo zeroes a byte slice in pure Go (fallback for non-AVX2).
func zeroBufferGo(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
