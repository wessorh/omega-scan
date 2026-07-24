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
// By default, TLS is used with system root CAs.  Pass insecure=true
// to skip TLS (for development servers without certificates).
// Pass caCert to use a custom CA.  Pass clientCert+clientKey for mTLS.
// Pass tlsServerName to override the TLS hostname check (useful when
// connecting by IP to a server with a named certificate).
func NewClient(serverAddr, caCert, clientCert, clientKey, tlsServerName string, insecureConn bool) (*Client, error) {
	var opts []grpc.DialOption

	if insecureConn {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsCfg, err := loadTLSConfig(caCert, clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("tls config: %w", err)
		}
		if tlsServerName != "" {
			tlsCfg.ServerName = tlsServerName
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}

	opts = append(opts,
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16<<20)),
	)

	conn, err := grpc.DialContext(context.Background(), serverAddr, opts...)
	if err != nil {
		hint := ""
		if !insecureConn {
			hint = " (is the server using a self-signed cert? try --insecure)"
		}
		return nil, fmt.Errorf("dial %s: %w%s", serverAddr, err, hint)
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
