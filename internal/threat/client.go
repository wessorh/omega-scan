package threat

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	omegav1 "github.com/support-intelligence/omega-scan/api/omega/v1"
)

// Client wraps the OmegaScan gRPC client.
type Client struct {
	conn *grpc.ClientConn
	cli  omegav1.OmegaScanClient
}

// NewClient creates a new gRPC client connection.
//
// If caCert, clientCert, and clientKey are all empty, an insecure connection
// is used (suitable for development).  For production, provide paths to PEM
// files for mutual TLS.
func NewClient(serverAddr, caCert, clientCert, clientKey string) (*Client, error) {
	var opts []grpc.DialOption

	if caCert == "" && clientCert == "" && clientKey == "" {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsCfg, err := loadTLSConfig(caCert, clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("tls config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}

	opts = append(opts, grpc.WithBlock(), grpc.WithDefaultCallOptions(
		grpc.MaxCallRecvMsgSize(16<<20), // 16 MiB
	))

	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, serverAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", serverAddr, err)
	}

	return &Client{
		conn: conn,
		cli:  omegav1.NewOmegaScanClient(conn),
	}, nil
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Lookup queries threat intelligence for a scanned artifact.
func (c *Client) Lookup(ctx context.Context, req *omegav1.LookupRequest) (*omegav1.LookupResponse, error) {
	resp, err := c.cli.Lookup(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("lookup: %w", err)
	}
	return resp, nil
}

// ── TLS helpers ─────────────────────────────────────────────────────────

const grpcTimeout = 10 * time.Second

func loadTLSConfig(caCert, clientCert, clientKey string) (*tls.Config, error) {
	cfg := &tls.Config{}

	if caCert != "" {
		caPEM, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		cfg.RootCAs = pool
	}

	if clientCert != "" && clientKey != "" {
		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}
