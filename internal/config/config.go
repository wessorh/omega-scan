package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config holds all client configuration.
type Config struct {
	Server ServerConfig `toml:"server"`
	Auth   AuthConfig   `toml:"auth"`
	Scan   ScanConfig   `toml:"scan"`
	Output OutputConfig `toml:"output"`
}

type ServerConfig struct {
	Address       string `toml:"address"`
	Insecure      bool   `toml:"insecure"`
	TLSServerName string `toml:"tls_server_name"`
	TLSCA         string `toml:"tls_ca"`
	TLSCert       string `toml:"tls_cert"`
	TLSKey        string `toml:"tls_key"`
}

type AuthConfig struct {
	APIToken string `toml:"api_token"`
}

type ScanConfig struct {
	Order            int  `toml:"order"`
	Threads          int  `toml:"threads"`
	ErrorsAsWarnings bool `toml:"errors_as_warnings"`
}

type OutputConfig struct {
	JSON    bool `toml:"json"`
	Stats   bool `toml:"stats"`
	Verbose bool `toml:"verbose"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Scan: ScanConfig{
			Threads: 2,
		},
	}
}

// LoadConfig reads a TOML config file.  If path is empty, returns defaults.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path != "" {
		if _, err := toml.DecodeFile(path, &cfg); err != nil {
			if !os.IsNotExist(err) {
				return cfg, fmt.Errorf("config %q: %w", path, err)
			}
		}
	}
	return cfg, nil
}
