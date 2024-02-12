package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Mode      Mode            `toml:"-"`
	Region    string          `toml:"region"`
	Service   ServiceConfig   `toml:"service"`
	Admin     AdminConfig     `toml:"admin"`
	Endpoints EndpointsConfig `toml:"endpoints"`
	KMS       KMSConfig       `toml:"kms"`
	Database  DatabaseConfig  `toml:"database"`
}

type AdminConfig struct {
	PublicKey string `toml:"public_key"`
}

type ServiceConfig struct {
	Mode          string `toml:"mode"`
	VSock         bool   `toml:"vsock"`
	UseNSM        bool   `toml:"use_nsm"`
	EnclavePort   uint32 `toml:"enclave_port"`
	ProxyPort     uint32 `toml:"proxy_port"`
	DebugProfiler bool   `toml:"debug_profiler"`
}

type EndpointsConfig struct {
	AWSEndpoint    string `toml:"aws_endpoint"`
	MetadataServer string `toml:"metadata_server"`
	WaasAPIServer  string `toml:"waas_api_server"`
}

type KMSConfig struct {
	TenantKeys         []string `toml:"tenant_keys"`
	DefaultSessionKeys []string `toml:"default_session_keys"`
}

type DatabaseConfig struct {
	TenantsTable  string `toml:"tenants_table"`
	AccountsTable string `toml:"accounts_table"`
	SessionsTable string `toml:"sessions_table"`
}

func New() (*Config, error) {
	fileName := os.Getenv("CONFIG")
	var cfg Config
	if _, err := toml.DecodeFile(fileName, &cfg); err != nil {
		return nil, err
	}

	var mode Mode
	switch cfg.Service.Mode {
	case "local":
		mode = LocalMode
	case "dev", "development":
		mode = DevelopmentMode
	case "prod", "production":
		mode = ProductionMode
	default:
		return nil, fmt.Errorf("config service.mode value is invalid, must be one of \"development\", \"dev\", \"production\" or \"prod\"")
	}
	cfg.Mode = mode
	cfg.Service.Mode = mode.String()

	return &cfg, nil
}

type Mode uint32

const (
	LocalMode Mode = iota
	DevelopmentMode
	ProductionMode
)

func (m Mode) String() string {
	switch m {
	case LocalMode:
		return "local"
	case DevelopmentMode:
		return "development"
	case ProductionMode:
		return "production"
	default:
		return ""
	}
}
