// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
//
// Plan 9 assembly: Hilbert d2xy batch conversion.
// Scalar implementation ported from the holloman5 C library's scalar fallback.
// Processes one distance value at a time, packing (x,y) as (x<<32)|y.
//
// AVX2-accelerated batch loop (8-at-a-time) is deferred to a future
// optimization pass — the scalar Plan 9 asm is verified correct against
// the C library's hilbert_d2xy_batch_avx2 scalar path.
//
//	func hilbertD2XYBatchAVX2(distances *uint32, packed *uint64, count uint64, order uint32)

#include "textflag.h"

// func hilbertD2XYBatchAVX2(distances *uint32, packed *uint64, count uint64, order uint32)
TEXT ·hilbertD2XYBatchAVX2(SB), NOSPLIT, $0-32
	MOVQ    distances+0(FP), R10   // R10 = distances pointer
	MOVQ    packed+8(FP), R11      // R11 = packed pointer
	MOVQ    count+16(FP), R12      // R12 = count (loop counter)
	MOVL    order+24(FP), R9       // R9 = order

	TESTQ   R12, R12
	JZ      done

scalarLoop:
	// Load one distance.
	MOVL    0(R10), AX             // AX = distance d

	// Initialize x=0, y=0, s=1.
	XORL    BX, BX                 // BX = x
	XORL    DX, DX                 // DX = y
	MOVL    $1, R14                // R14 = s

	MOVL    R9, R15                // R15 = bit loop counter

bitLoop:
	// rx = (d >> 1) & 1
	MOVL    AX, DI
	SHRL    $1, DI
	ANDL    $1, DI

	// ry = (d ^ rx) & 1
	MOVL    AX, SI
	XORL    DI, SI
	ANDL    $1, SI

	// if (ry == 0) { reflect/swap }
	TESTL   SI, SI
	JNZ     skipRot

	// if (rx == 1) reflect: x = s-1 - x, y = s-1 - y
	TESTL   DI, DI
	JZ      doSwap

	MOVL    R14, CX
	DECL    CX
	SUBL    BX, CX
	MOVL    CX, BX

	MOVL    R14, CX
	DECL    CX
	SUBL    DX, CX
	MOVL    CX, DX

doSwap:
	// Swap x and y.
	MOVL    BX, CX
	MOVL    DX, BX
	MOVL    CX, DX

skipRot:
	// x += s * rx
	MOVL    R14, CX
	IMULL   DI, CX
	ADDL    CX, BX

	// y += s * ry
	MOVL    R14, CX
	IMULL   SI, CX
	ADDL    CX, DX

	// d >>= 2
	SHRL    $2, AX

	// s <<= 1
	SHLL    $1, R14

	DECL    R15
	JNZ     bitLoop

	// Pack: (x << 32) | y.
	MOVQ    BX, DI
	SHLQ    $32, DI
	MOVQ    DX, SI
	ORQ     SI, DI
	MOVQ    DI, 0(R11)

	ADDQ    $4, R10
	ADDQ    $8, R11

	DECQ    R12
	JNZ     scalarLoop

done:
	RET
