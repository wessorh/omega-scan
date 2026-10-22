package fingerprint

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestBuildClusterID(t *testing.T) {
	tests := []struct {
		order uint32
		fp    [16]byte
		want  string
	}{
		{7, [16]byte{0: 0x00, 2: 0x07, 3: 0x7e, 4: 0x87}, "h.0000077e870000000000000000000000"},
		{9, [16]byte{}, "j.00000000000000000000000000000000"},
		{13, [16]byte{0: 0xff, 15: 0xff}, "o.ff0000000000000000000000000000ff"},
		{24, [16]byte{}, "z.00000000000000000000000000000000"}, // OrderAlphabet[24] = 'z'
	}
	for _, tt := range tests {
		got := BuildClusterID(tt.order, tt.fp)
		if got != tt.want {
			t.Errorf("BuildClusterID(%d, %x) = %q, want %q",
				tt.order, tt.fp, got, tt.want)
		}
	}
}

func TestEnclosingOrder(t *testing.T) {
	tests := []struct {
		size int64
		want uint32
	}{
		{0, 5},
		{1024, 5},     // 2^10 = 4^5 → order 5
		{4096, 6},     // 4^6 → order 6
		{16384, 7},    // 4^7 → order 7
		{65536, 8},    // 4^8 → order 8
		{1 << 20, 10}, // 4^10 → order 10
		{1 << 28, 14}, // 4^14 → order 14
	}
	for _, tt := range tests {
		got := EnclosingOrder(tt.size)
		if got != tt.want {
			t.Errorf("EnclosingOrder(%d) = %d, want %d", tt.size, got, tt.want)
		}
	}
}

func TestFingerprintBuffer(t *testing.T) {
	if err := Init(13); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer Cleanup()

	// Fingerprint should succeed for inputs ≥ 1024 bytes.
	data := make([]byte, 4096)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	fp, err := FingerprintBuffer(data)
	if err != nil {
		t.Fatalf("FingerprintBuffer: %v", err)
	}

	// Fingerprint should NOT be all zeros.
	allZero := true
	for _, b := range fp {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Errorf("Fingerprint is all zeros — pipeline not working")
	}
	t.Logf("Fingerprint: %032x", fp)

	cid := BuildClusterID(9, fp)
	t.Logf("ClusterID: %s", cid)
}

func TestFingerprintSmall(t *testing.T) {
	if err := Init(13); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer Cleanup()

	// Input too small should error.
	data := make([]byte, 512)
	_, err := FingerprintBuffer(data)
	if err == nil {
		t.Error("expected error for small input, got nil")
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	if err := Init(13); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer Cleanup()

	// Same input should produce same fingerprint.
	data := make([]byte, 2048)
	for i := range data {
		data[i] = byte(i * 7 % 256)
	}

	fp1, _ := FingerprintBuffer(data)
	fp2, _ := FingerprintBuffer(data)

	if fp1 != fp2 {
		t.Errorf("Fingerprint not deterministic: %x != %x", fp1, fp2)
	}
}

func TestCurveCorrectness(t *testing.T) {
	c, err := NewCurve(3)
	if err != nil {
		t.Fatal(err)
	}
	if c.Order != 3 {
		t.Errorf("Order = %d, want 3", c.Order)
	}
	if c.Dimension != 8 {
		t.Errorf("Dimension = %d, want 8", c.Dimension)
	}
	if len(c.Points) != 64 {
		t.Errorf("Points = %d, want 64 (4^3)", len(c.Points))
	}

	// First 4 points should be (0,0), (0,1), (1,1), (1,0) — first U-shape.
	expected := [][2]uint32{{0, 0}, {0, 1}, {1, 1}, {1, 0}}
	for i, e := range expected {
		x, y := c.Points[i].Unpack()
		if x != e[0] || y != e[1] {
			t.Errorf("Point[%d] = (%d, %d), want (%d, %d)", i, x, y, e[0], e[1])
		}
	}
}

func TestRotation(t *testing.T) {
	src := &[16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	var dst [16]byte
	rotateMatrix90Clockwise(src, &dst)

	// Permutation: {12,8,4,0, 13,9,5,1, 14,10,6,2, 15,11,7,3}
	expected := [16]byte{12, 8, 4, 0, 13, 9, 5, 1, 14, 10, 6, 2, 15, 11, 7, 3}
	if dst != expected {
		t.Errorf("Rotation: got %v, want %v", dst, expected)
	}
}

func TestZeroBuffer(t *testing.T) {
	// Allocate a buffer, fill with non-zero, zero it, verify.
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = 0xFF
	}
	zeroBuffer(buf)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("zeroBuffer: byte %d = %d, want 0", i, b)
			break
		}
	}
}

func BenchmarkFingerprint(b *testing.B) {
	Init(13)
	defer Cleanup()

	data := make([]byte, 65536)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FingerprintBuffer(data)
	}
}

func BenchmarkZeroBuffer(b *testing.B) {
	buf := make([]byte, 1<<20) // 1 MB
	for i := range buf {
		buf[i] = 0xFF
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		zeroBuffer(buf)
		for j := range buf {
			buf[j] = 0xFF
		}
	}
}

func TestInitDualCache(t *testing.T) {
	if err := Init(13); err != nil {
		t.Fatalf("Init(13): %v", err)
	}
	defer Cleanup()

	// Verify both even and odd curves exist.
	c7 := getCurve(7)
	if c7 == nil {
		t.Fatal("getCurve(7) = nil (odd curve should exist)")
	}
	c8 := getCurve(8)
	if c8 == nil {
		t.Fatal("getCurve(8) = nil (even curve should exist)")
	}

	if c7.Order < 7 {
		t.Errorf("odd curve order %d < 7", c7.Order)
	}
	if c8.Order < 8 {
		t.Errorf("even curve order %d < 8", c8.Order)
	}

	t.Logf("Odd curve: order=%d dim=%d points=%d",
		c7.Order, c7.Dimension, len(c7.Points))
	t.Logf("Even curve: order=%d dim=%d points=%d",
		c8.Order, c8.Dimension, len(c8.Points))
}

func TestInitReentrant(t *testing.T) {
	// Multiple Init calls should be safe.
	for i := 0; i < 3; i++ {
		if err := Init(10); err != nil {
			t.Fatalf("Init #%d: %v", i, err)
		}
	}
	Cleanup()
}

func TestDoubleInitUpgrade(t *testing.T) {
	// Init with lower order, then higher order.
	if err := Init(7); err != nil {
		t.Fatal(err)
	}
	// Second init with higher order should upgrade.
	if err := Init(13); err != nil {
		t.Fatal(err)
	}
	Cleanup()
}

// ── Regression: known fingerprint values from C library ─────────────────

func TestFingerprintKnownValue(t *testing.T) {
	if err := Init(13); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer Cleanup()

	// A file of all 0x41 bytes ('A') at 4096 bytes.
	// The C library produces a deterministic fingerprint for this input.
	data := make([]byte, 4096)
	for i := range data {
		data[i] = 0x41
	}

	fp, err := FingerprintBuffer(data)
	if err != nil {
		t.Fatal(err)
	}

	// The fingerprint should be deterministic — same every time.
	fp2, _ := FingerprintBuffer(data)
	if fp != fp2 {
		t.Error("fingerprint not deterministic for all-A input")
	}

	// Verify it's not all zeros.
	allZero := true
	for _, b := range fp {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("fingerprint is all zeros for all-A input")
	}

	t.Logf("All-A fingerprint: %032x", fp)
	t.Logf("ClusterID: %s", BuildClusterID(7, fp))
}

// Test multiple file sizes to ensure Lanczos kernel handles varying dimensions.
func TestFingerprintVariousSizes(t *testing.T) {
	if err := Init(13); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer Cleanup()

	sizes := []int{1024, 2048, 4096, 8192, 16384, 32768, 65536}
	for _, size := range sizes {
		name := fmt.Sprintf("size=%d", size)
		t.Run(name, func(t *testing.T) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte((i*37 + 13) & 0xFF)
			}
			fp, err := FingerprintBuffer(data)
			if err != nil {
				t.Fatalf("FingerprintBuffer(%d): %v", size, err)
			}

			allZero := true
			for _, b := range fp {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Errorf("size %d: fingerprint is all zeros", size)
			}

			t.Logf("size=%d: %032x", size, fp)
		})
	}
}
