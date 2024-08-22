package config

type MigrationsConfig struct {
	OIDCToStytch []OIDCToStytchConfig `toml:"oidc_to_stytch"`
}

type OIDCToStytchConfig struct {
	SequenceProject uint64 `toml:"sequence_project"`
	StytchProject   string `toml:"stytch_project"`
	FromIssuer      string `toml:"from_issuer"`
}
