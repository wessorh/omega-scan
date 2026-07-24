package scanner

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/support-intelligence/omega-scan/internal/fingerprint"
)

// Result holds the scan output for a single target.
type Result struct {
	Path      string        // file path or URL
	Size      int64         // file size in bytes
	SHA1      string        // hex-encoded SHA-1 (40 chars)
	SHA256    string        // hex-encoded SHA-256 (64 chars)
	ClusterID string        // e.g. "h.00286058000750550000040500000000"
	Order     uint32        // Hilbert curve order
	Fingerprint [16]byte    // raw 16-byte fingerprint
	MIMEType  string        // detected MIME type
	Err       error
	Elapsed   time.Duration
}

// Config holds options for scanning.
type Config struct {
	MaxFileSize int64         // max file/URL body size (default: 256 MiB)
	Timeout     time.Duration // HTTP fetch timeout (default: 30s)
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxFileSize: 256 << 20, // 256 MiB
		Timeout:     30 * time.Second,
	}
}

// ScanFile scans a single local file.
func ScanFile(path string, cfg Config) (*Result, error) {
	start := time.Now()

	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if fi.Size() > cfg.MaxFileSize {
		return nil, fmt.Errorf("%s: file too large (%d > %d)", path, fi.Size(), cfg.MaxFileSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return scanBytes(path, data, fi.Size(), cfg, start)
}

// ScanURL fetches and scans a remote URL.
func ScanURL(rawURL string, cfg Config) (*Result, error) {
	start := time.Now()

	client := &http.Client{Timeout: cfg.Timeout}

	// HEAD to check size
	headResp, err := client.Head(rawURL)
	if err != nil {
		return nil, fmt.Errorf("HEAD %s: %w", rawURL, err)
	}
	headResp.Body.Close()

	if headResp.ContentLength > cfg.MaxFileSize {
		return nil, fmt.Errorf("%s: content too large (%d > %d)",
			rawURL, headResp.ContentLength, cfg.MaxFileSize)
	}

	// GET
	getResp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer getResp.Body.Close()

	size := getResp.ContentLength
	data, err := io.ReadAll(io.LimitReader(getResp.Body, cfg.MaxFileSize))
	if err != nil {
		return nil, fmt.Errorf("read body %s: %w", rawURL, err)
	}
	if size <= 0 {
		size = int64(len(data))
	}

	return scanBytes(rawURL, data, size, cfg, start)
}

// Scan detects whether target is a file, directory, or URL and scans accordingly.
// Directories are recursed into — each file is scanned and results are streamed
// via the callback.  Returns the number of files scanned.
//
// The yield callback should return true to continue scanning, false to abort.
func Scan(target string, cfg Config, yield func(*Result) bool) (int, error) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		r, err := ScanURL(target, cfg)
		if err != nil {
			return 0, err
		}
		yield(r)
		return 1, nil
	}

	fi, err := os.Stat(target)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", target, err)
	}

	if fi.IsDir() {
		return scanDir(target, cfg, yield)
	}

	r, err := ScanFile(target, cfg)
	if err != nil {
		return 0, err
	}
	yield(r)
	return 1, nil
}

func scanDir(dir string, cfg Config, yield func(*Result) bool) (int, error) {
	count := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("readdir %s: %w", dir, err)
	}
	for _, entry := range entries {
		path := dir + "/" + entry.Name()
		if entry.IsDir() {
			n, abort := scanDir(path, cfg, yield)
			count += n
			if abort != nil {
				return count, abort
			}
			continue
		}
		if !entry.Type().IsRegular() {
			continue
		}
		r, err := ScanFile(path, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			if !yield(nil) {
				return count, fmt.Errorf("aborted after error in %s", path)
			}
			continue
		}
		if !yield(r) {
			return count, nil
		}
		count++
	}
	return count, nil
}

var _ = fmt.Fprintf // keep fmt import

func scanBytes(path string, data []byte, size int64, cfg Config, start time.Time) (*Result, error) {
	if len(data) < 1024 {
		return nil, fmt.Errorf("%s: too small (%d bytes, minimum 1024)", path, len(data))
	}

	// SHA-1
	s1 := sha1.Sum(data)

	// SHA-256
	s256 := sha256.Sum256(data)

	// Holloman fingerprint
	fp, err := fingerprint.FingerprintBuffer(data)
	if err != nil {
		return nil, fmt.Errorf("%s: fingerprint: %w", path, err)
	}

	order := fingerprint.EnclosingOrder(size)
	clusterID := fingerprint.BuildClusterID(order, fp)

	return &Result{
		Path:        path,
		Size:        size,
		SHA1:        hex.EncodeToString(s1[:]),
		SHA256:      hex.EncodeToString(s256[:]),
		ClusterID:   clusterID,
		Order:       order,
		Fingerprint: fp,
		Elapsed:     time.Since(start),
	}, nil
}

// RequiresInit returns true if the fingerprint library hasn't been initialised.
func RequiresInit() bool {
	// Try a small dummy fingerprint — if it fails with "not initialised", return true.
	_, err := fingerprint.FingerprintBuffer(make([]byte, 1024))
	return err != nil
}
