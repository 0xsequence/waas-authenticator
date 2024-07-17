package proto

import (
	"fmt"
	"strings"
)

func (id Identity) String() string {
	switch id.Type {
	case IdentityType_Guest, IdentityType_Email:
		return string(id.Type) + ":" + id.Subject
	case IdentityType_OIDC, IdentityType_PlayFab, IdentityType_Stytch:
		return string(id.Type) + ":" + id.Issuer + "#" + id.Subject
	default:
		return ""
	}
}

func (id *Identity) FromString(s string) error {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid identity format: %s", s)
	}

	idType := IdentityType(parts[0])
	switch idType {
	case IdentityType_Guest:
		id.Type = IdentityType_Guest
		id.Subject = parts[1]

	case IdentityType_OIDC, IdentityType_PlayFab, IdentityType_Stytch:
		innerParts := strings.SplitN(parts[1], "#", 2)
		if len(innerParts) != 2 {
			return fmt.Errorf("invalid identity format: %s", parts[1])
		}
		id.Type = idType
		id.Issuer = innerParts[0]
		id.Subject = innerParts[1]

	case IdentityType_Email:
		id.Type = IdentityType_Email
		id.Subject = parts[1]

	default:
		return fmt.Errorf("invalid identity type: %s", parts[0])
	}
	return nil
}
