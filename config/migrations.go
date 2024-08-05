package config

type MigrationsConfig struct {
	OIDCToStytch []OIDCToStytchConfig `toml:"oidc_to_stytch"`
}

type OIDCToStytchConfig struct {
	ProjectID       uint64 `toml:"project_id"`
	StytchProjectID string `toml:"stytch_project_id"`
	FromIssuer      string `toml:"from_issuer"`
}
