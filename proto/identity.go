package proto

import (
	"strconv"
)

func (id Identity) String() string {
	return strconv.Itoa(int(id.ProjectID)) + "#" + id.Issuer + "#" + id.Subject
}

func (s SessionData) Identity() Identity {
	return Identity{
		ProjectID: s.ProjectID,
		Issuer:    s.Issuer,
		Subject:   s.Subject,
	}
}
