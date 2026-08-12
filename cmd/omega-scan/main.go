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
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/denisbrodbeck/machineid"
	"github.com/support-intelligence/omega-scan/internal/config"
	"github.com/support-intelligence/omega-scan/internal/fingerprint"
	"github.com/support-intelligence/omega-scan/internal/scanner"
	"github.com/support-intelligence/omega-scan/internal/threat"

	omegav1 "github.com/support-intelligence/omega-scan/api/omega/v1"
)

func applyDefault(field **string, cfgVal string) {
	if **field == "" {
		**field = cfgVal
	}
}

func applyDefaultBool(field **bool, cfgVal bool) {
	if !**field {
		**field = cfgVal
	}
}

func getMachineID() string {
	id, err := machineid.ID()
	if err != nil {
		return "unknown"
	}
	return id
}

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
		fmt.Println("machine-id:", getMachineID())
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
	configPath := fs.String("config", "", "TOML config file path")
	serverAddr := fs.String("server", "api.dewile.net:8443", "gRPC server address")
	tlsCA := fs.String("tls-ca", "", "CA certificate PEM file (default: system roots)")
	tlsCert := fs.String("tls-cert", "", "Client certificate PEM file (mTLS)")
	tlsKey := fs.String("tls-key", "", "Client key PEM file (mTLS)")
	insecureConn := fs.Bool("insecure", false, "Skip TLS (for development servers)")
	tlsServerName := fs.String("tls-server-name", "", "Override TLS hostname (for IP connections to named certs)")
	apiToken := fs.String("api-token", "", "API token for higher rate limits")
	errorsAsWarnings := fs.Bool("errors-as-warnings", false, "Continue processing directory after errors")
	fpOrder := fs.Int("order", 0, "Hilbert curve order (0=auto)")
	jsonOut := fs.Bool("json", false, "Output JSON")
	verbose := fs.Bool("v", false, "Verbose: print machine ID")
	threads := fs.Int("threads", 0, "Number of parallel scan workers (0=use config default)")
	statsOut := fs.Bool("stats", false, "Print aggregate statistics at exit")

	fs.Parse(os.Args[2:])

	// Load config file.
	cliCfg, _ := config.LoadConfig(*configPath)

	// Apply config defaults for flags not explicitly set.
	applyDefault(&serverAddr, cliCfg.Server.Address)
	applyDefaultBool(&insecureConn, cliCfg.Server.Insecure)
	applyDefault(&tlsServerName, cliCfg.Server.TLSServerName)
	applyDefault(&tlsCA, cliCfg.Server.TLSCA)
	applyDefault(&tlsCert, cliCfg.Server.TLSCert)
	applyDefault(&tlsKey, cliCfg.Server.TLSKey)
	applyDefault(&apiToken, cliCfg.Auth.APIToken)

		// Environment variable overrides.
		if v := os.Getenv("DEWILE_SERVER"); v != "" {
			*serverAddr = v
		}
		if v := os.Getenv("DEWILE_API_KEY"); v != "" {
			*apiToken = v
		}
	if *fpOrder == 0 { *fpOrder = cliCfg.Scan.Order }
	if *threads == 0 { *threads = cliCfg.Scan.Threads }
	applyDefaultBool(&errorsAsWarnings, cliCfg.Scan.ErrorsAsWarnings)
	applyDefaultBool(&jsonOut, cliCfg.Output.JSON)
	applyDefaultBool(&statsOut, cliCfg.Output.Stats)
	applyDefaultBool(&verbose, cliCfg.Output.Verbose)

	// Ensure threads has a sensible minimum.
	if *threads < 1 { *threads = 2 }
	targets := fs.Args()
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one target required")
		os.Exit(1)
	}

	// ── Init fingerprint library ──────────────────────────────────────────
	order := uint32(*fpOrder)
	if order == 0 {
		order = 11 // order 11 covers files up to ~4 MB (8 MB cache)
	}
	log.Printf("initializing holloman3 fingerprint library (order %d)...", order)
	if err := fingerprint.Init(order); err != nil {
		log.Fatalf("fingerprint init: %v", err)
	}
	defer fingerprint.Cleanup()
	log.Printf("fingerprint library ready")

	// ── Machine ID ────────────────────────────────────────────────────────
	machineID := getMachineID()
	if *verbose {
		fmt.Fprintf(os.Stderr, "machine-id: %s\n", machineID)
	}

	// ── gRPC client (optional) ────────────────────────────────────────────
	var tc *threat.Client
	if *serverAddr != "" {
		var err error
		tc, err = threat.NewClient(*serverAddr, *tlsCA, *tlsCert, *tlsKey, *tlsServerName, *insecureConn)
		if err != nil {
			log.Fatalf("gRPC client: %v", err)
		}
		defer tc.Close()
	}

	// ── Stats ───────────────────────────────────────────────────────────────
	type stats struct {
		mu          sync.Mutex
		calls       int
		malicious   int
		undetected  int
		families    map[string]int
		categories  map[string]int
		severities  map[string]int
	}
	st := &stats{
		families:   make(map[string]int),
		categories: make(map[string]int),
		severities: make(map[string]int),
	}
	recordStats := func(resp *omegav1.LookupResponse) {
		if resp == nil {
			return
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		st.calls++
		if resp.Malicious {
			st.malicious++
		} else {
			st.undetected++
		}
		if resp.Family != "" {
			st.families[resp.Family]++
		}
		if resp.Category != "" {
			st.categories[resp.Category]++
		}
		st.severities[resp.Severity.String()]++
	}
	printStats := func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		fmt.Fprintf(os.Stderr, "\n── Scan Statistics ──\n")
		fmt.Fprintf(os.Stderr, "  Total lookups:     %d\n", st.calls)
		fmt.Fprintf(os.Stderr, "  Malicious:         %d\n", st.malicious)
		fmt.Fprintf(os.Stderr, "  Undetected:        %d\n", st.undetected)
		fmt.Fprintf(os.Stderr, "  Severities:\n")
		for _, s := range []string{"SEVERITY_CRITICAL", "SEVERITY_HIGH", "SEVERITY_MEDIUM", "SEVERITY_LOW", "SEVERITY_INFO", "SEVERITY_UNSPECIFIED"} {
			if n, ok := st.severities[s]; ok {
				fmt.Fprintf(os.Stderr, "    %-22s %d\n", strings.TrimPrefix(s, "SEVERITY_"), n)
			}
		}
		if len(st.families) > 0 {
			fmt.Fprintf(os.Stderr, "  Top families:\n")
			type kv struct{ k string; v int }
			var fams []kv
			for k, v := range st.families { fams = append(fams, kv{k, v}) }
			sort.Slice(fams, func(i, j int) bool { return fams[i].v > fams[j].v })
			for _, f := range fams[:min(10, len(fams))] {
				fmt.Fprintf(os.Stderr, "    %-40s %d\n", f.k, f.v)
			}
		}
		if len(st.categories) > 0 {
			fmt.Fprintf(os.Stderr, "  Categories:\n")
			type kv struct{ k string; v int }
			var cats []kv
			for k, v := range st.categories { cats = append(cats, kv{k, v}) }
			sort.Slice(cats, func(i, j int) bool { return cats[i].v > cats[j].v })
			for _, c := range cats[:min(5, len(cats))] {
				fmt.Fprintf(os.Stderr, "    %-40s %d\n", c.k, c.v)
			}
		}
	}
	if *statsOut {
		defer printStats()
		// Print on Ctrl+C as well.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			printStats()
			os.Exit(0)
		}()
	}

	scanCfg := scanner.DefaultConfig()

	// ── Scan callback (thread-safe for parallel workers) ──────────────────
	var (
		first   = true
		outMu   sync.Mutex
	)
	printResult := func(result *scanner.Result) bool {
		outMu.Lock()
		defer outMu.Unlock()
		// nil result means an error occurred on a file in the directory.
		if result == nil {
			if *errorsAsWarnings {
				return true // continue
			}
			return false // stop
		}

		if !*jsonOut {
			if !first {
				fmt.Println()
			}
			first = false
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
			return true
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
				ClientId:     machineID,
				ApiToken:     *apiToken,
			}
			if strings.HasPrefix(result.Path, "http") {
				req.ArtifactType = omegav1.ArtifactType_ARTIFACT_TYPE_URL
				req.Uri = result.Path
			}

			resp, err := tc.Lookup(ctx, req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  gRPC lookup: ERROR: %v\n", err)
			} else {
				recordStats(resp)
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
			}
		}
		return true
	}

	// ── Collect file paths from all targets ────────────────────────────────
	var files []string
	for _, target := range targets {
		collectFiles(target, &files)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "error: no files to scan")
		os.Exit(1)
	}

	// ── Worker pool ───────────────────────────────────────────────────────
	nWorkers := *threads
	if nWorkers < 1 {
		nWorkers = 1
	}
	if nWorkers > len(files) {
		nWorkers = len(files)
	}

	fileCh := make(chan string, len(files))
	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)

	var wg sync.WaitGroup

	for i := 0; i < nWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileCh {
				result, err := scanner.ScanFile(path, scanCfg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
					continue
				}
				printResult(result)
			}
		}()
	}
	wg.Wait()
}

func collectFiles(target string, files *[]string) {
	fi, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", target, err)
		return
	}
	if fi.IsDir() {
		entries, _ := os.ReadDir(target)
		for _, e := range entries {
			// Skip symlinks inside directories to avoid loops.
			if e.Type()&os.ModeSymlink != 0 {
				continue
			}
			collectFiles(target+"/"+e.Name(), files)
		}
		return
	}
	if fi.Mode().IsRegular() {
		*files = append(*files, target)
	}
}
