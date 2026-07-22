// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
//
// Plan 9 assembly: AVX2-accelerated buffer zeroing.
// Matches hilbert_zero_buffer_avx2 in the holloman5 C library.
//
//	func zeroBufferAVX2(buf unsafe.Pointer, n int)

#include "textflag.h"

// func zeroBufferAVX2(buf unsafe.Pointer, n int)
TEXT ·zeroBufferAVX2(SB), NOSPLIT, $0-16
	MOVQ    buf+0(FP), DI    // DI = buffer pointer
	MOVQ    n+8(FP), SI      // SI = length

	// Check if length is zero
	TESTQ   SI, SI
	JZ      done

	// Create zero vector (256-bit)
	VPXOR   Y0, Y0, Y0

	// Calculate number of 128-byte chunks
	MOVQ    SI, CX
	SHRQ    $7, CX            // divide by 128
	JZ      small

loop128:
	// Zero 128 bytes at a time (4 × 32-byte stores, unrolled)
	VMOVDQU Y0, 0(DI)
	VMOVDQU Y0, 32(DI)
	VMOVDQU Y0, 64(DI)
	VMOVDQU Y0, 96(DI)
	ADDQ    $128, DI
	DECQ    CX
	JNZ     loop128

small:
	// Handle remaining 32-byte chunks (0–96 bytes)
	MOVQ    SI, CX
	ANDQ    $127, CX          // get remainder of /128
	SHRQ    $5, CX             // divide by 32
	JZ      remainder

loop32:
	VMOVDQU Y0, 0(DI)
	ADDQ    $32, DI
	DECQ    CX
	JNZ     loop32

remainder:
	// Handle remaining bytes (0–31) with scalar stores
	ANDQ    $31, SI            // get remainder of /32
	JZ      done

	XORL    AX, AX
byteLoop:
	MOVB    AL, 0(DI)
	INCQ    DI
	DECQ    SI
	JNZ     byteLoop

done:
	VZEROUPPER
	RET
