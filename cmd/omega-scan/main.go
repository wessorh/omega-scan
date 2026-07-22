// omega-scan — holloman3 file and URL scanner with gRPC threat lookup.
//
// Usage:
//
//	omega-scan scan [flags] <file-or-url> [file-or-url ...]
//
// Flags:
//
//	--server     string   gRPC server address (default "localhost:8443")
//	--tls-ca     string   CA certificate PEM file
//	--tls-cert   string   Client certificate PEM file
//	--tls-key    string   Client key PEM file
//	--order      int      Hilbert curve order (0 = auto, default 0)
//	--json                Output JSON instead of tabular
//	--no-lookup           Skip gRPC lookup (local scan only)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/support-intelligence/omega-scan/internal/fingerprint"
	"github.com/support-intelligence/omega-scan/internal/scanner"
	"github.com/support-intelligence/omega-scan/internal/threat"

	omegav1 "github.com/support-intelligence/omega-scan/api/omega/v1"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		scanCmd()
	case "version":
		fmt.Println(fingerprint.Version())
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `omega-scan — holloman3 file and URL scanner

Usage:
  omega-scan scan [flags] <file-or-url> [file-or-url ...]
  omega-scan version

Flags:
`)
	flag.CommandLine.SetOutput(os.Stderr)
	flag.PrintDefaults()
}

func scanCmd() {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	serverAddr := fs.String("server", "", "gRPC server address (e.g. localhost:8443)")
	tlsCA := fs.String("tls-ca", "", "CA certificate PEM file")
	tlsCert := fs.String("tls-cert", "", "Client certificate PEM file")
	tlsKey := fs.String("tls-key", "", "Client key PEM file")
	fpOrder := fs.Int("order", 0, "Hilbert curve order (0=auto)")
	jsonOut := fs.Bool("json", false, "Output JSON")
	noLookup := fs.Bool("no-lookup", false, "Skip gRPC lookup")
	_ = fs.String("debug", "", "") // reserved

	fs.Parse(os.Args[2:])
	targets := fs.Args()
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one target required")
		os.Exit(1)
	}

	// ── Init fingerprint library ──────────────────────────────────────────
	order := uint32(*fpOrder)
	if order == 0 {
		order = 13 // reasonable default for general use (64 MB cache)
	}
	log.Printf("initializing holloman3 fingerprint library (order %d)...", order)
	if err := fingerprint.Init(order); err != nil {
		log.Fatalf("fingerprint init: %v", err)
	}
	defer fingerprint.Cleanup()
	log.Printf("fingerprint library ready")

	// ── gRPC client (optional) ────────────────────────────────────────────
	var tc *threat.Client
	if *serverAddr != "" && !*noLookup {
		var err error
		tc, err = threat.NewClient(*serverAddr, *tlsCA, *tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("gRPC client: %v", err)
		}
		defer tc.Close()
	}

	cfg := scanner.DefaultConfig()

	// ── Scan loop ─────────────────────────────────────────────────────────
	for i, target := range targets {
		if i > 0 && !*jsonOut {
			fmt.Println()
		}

		result, err := scanner.Scan(target, cfg)
		if err != nil {
			if *jsonOut {
				json.NewEncoder(os.Stdout).Encode(map[string]string{
					"target": target,
					"error":  err.Error(),
				})
			} else {
				fmt.Fprintf(os.Stderr, "%s: ERROR: %v\n", target, err)
			}
			continue
		}

		if *jsonOut {
			output := map[string]interface{}{
				"path":       result.Path,
				"size":       result.Size,
				"sha1":       result.SHA1,
				"sha256":     result.SHA256,
				"cluster_id": result.ClusterID,
				"order":      result.Order,
				"elapsed":    result.Elapsed.String(),
			}
			json.NewEncoder(os.Stdout).Encode(output)
			continue
		}

		// Human-readable output
		fmt.Printf("%-42s %s\n", "Path:", result.Path)
		fmt.Printf("%-42s %d bytes\n", "Size:", result.Size)
		fmt.Printf("%-42s %s\n", "SHA-1:", result.SHA1)
		fmt.Printf("%-42s %s\n", "SHA-256:", result.SHA256)
		fmt.Printf("%-42s %s\n", "Cluster ID:", result.ClusterID)
		fmt.Printf("%-42s %d\n", "Order:", result.Order)
		fmt.Printf("%-42s %v\n", "Elapsed:", result.Elapsed.Round(time.Microsecond))

		// gRPC lookup
		if tc != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			req := &omegav1.LookupRequest{
				ClusterId:    result.ClusterID,
				Sha1:         result.SHA1,
				Sha256:       result.SHA256,
				ArtifactType: omegav1.ArtifactType_ARTIFACT_TYPE_FILE,
			}
			if strings.HasPrefix(result.Path, "http") {
				req.ArtifactType = omegav1.ArtifactType_ARTIFACT_TYPE_URL
				req.Uri = result.Path
			}

			resp, err := tc.Lookup(ctx, req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  gRPC lookup: ERROR: %v\n", err)
			} else {
				fmt.Printf("%-42s %t\n", "Malicious:", resp.Malicious)
				fmt.Printf("%-42s %d\n", "Threat Score:", resp.ThreatScore)
				fmt.Printf("%-42s %s\n", "Severity:", resp.Severity.String())
				fmt.Printf("%-42s %s\n", "Family:", resp.Family)
				fmt.Printf("%-42s %s\n", "Category:", resp.Category)
				if len(resp.Tags) > 0 {
					fmt.Printf("%-42s %s\n", "Tags:", strings.Join(resp.Tags, ", "))
				}
				if resp.AvDetections > 0 {
					fmt.Printf("%-42s %d/%d\n", "AV Detections:",
						resp.AvDetections, resp.AvTotal)
				}
				if resp.ClusterSize > 0 {
					fmt.Printf("%-42s %d\n", "Cluster Size:", resp.ClusterSize)
				}
				if len(resp.NearestNeighbors) > 0 {
					fmt.Printf("%-42s\n", "Nearest Neighbors:")
					for _, n := range resp.NearestNeighbors {
						fmt.Printf("  %-40s hamming=%d family=%s size=%d\n",
							n.ClusterId, n.HammingDistance,
							n.Family, n.ClusterSize)
					}
				}
			}
		}
	}
}
