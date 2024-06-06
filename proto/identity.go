package proto

import (
	"fmt"
	"strings"
)

func (id Identity) String() string {
	switch id.Type {
	case IdentityType_OIDC:
		return string(id.Type) + ":" + id.Issuer + "#" + id.Subject
	case IdentityType_Email:
		return string(id.Type) + ":" + id.Email
	default:
		return ""
	}
}

func (id *Identity) FromString(s string) error {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid identity format: %s", s)
	}

	switch IdentityType(parts[0]) {
	case IdentityType_OIDC:
		oidcParts := strings.SplitN(parts[1], "#", 2)
		if len(oidcParts) != 2 {
			return fmt.Errorf("invalid OIDC identity format: %s", parts[1])
		}
		id.Type = IdentityType_OIDC
		id.Issuer = oidcParts[0]
		id.Subject = oidcParts[1]

	case IdentityType_Email:
		id.Type = IdentityType_Email
		id.Email = parts[1]

	default:
		return fmt.Errorf("invalid identity type: %s", parts[0])
	}
	return nil
}
