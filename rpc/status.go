package rpc

import (
	"context"
	"time"

	waasauthenticator "github.com/0xsequence/waas-authenticator"
	"github.com/0xsequence/waas-authenticator/proto"
)

func (s *RPC) Version(ctx context.Context) (*proto.Version, error) {
	return &proto.Version{
		WebrpcVersion: proto.WebRPCVersion(),
		SchemaVersion: proto.WebRPCSchemaVersion(),
		SchemaHash:    proto.WebRPCSchemaHash(),
		AppVersion:    waasauthenticator.GITCOMMIT,
	}, nil
}

func (s *RPC) RuntimeStatus(ctx context.Context) (*proto.RuntimeStatus, error) {
	status := &proto.RuntimeStatus{
		HealthOK:   true,
		StartTime:  s.startTime,
		Uptime:     uint64(time.Now().UTC().Sub(s.startTime).Seconds()),
		Ver:        waasauthenticator.VERSION,
		Branch:     waasauthenticator.GITBRANCH,
		CommitHash: waasauthenticator.GITCOMMIT,
	}
	return status, nil
}

func (s *RPC) Clock(ctx context.Context) (time.Time, error) {
	now := time.Now()
	return now, nil
}
