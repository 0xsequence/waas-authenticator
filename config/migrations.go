package config

type MigrationsConfig struct {
	OIDCToStytch []OIDCToStytchConfig `toml:"oidc_to_stytch"`
	Email        EmailMigrationConfig `toml:"oidc_to_email"`
}

type OIDCToStytchConfig struct {
	SequenceProject uint64 `toml:"sequence_project"`
	StytchProject   string `toml:"stytch_project"`
	FromIssuer      string `toml:"from_issuer"`
}

type EmailMigrationConfig struct {
	Enabled      bool     `toml:"enabled"`
	IssuerPrefix string   `toml:"issuer_prefix"`
	Projects     []uint64 `toml:"projects"`
}
