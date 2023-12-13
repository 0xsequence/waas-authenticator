package rpc

import (
	"context"
	"time"

	"github.com/0xsequence/waas-authenticator/proto"
)

func (s *RPC) Version(ctx context.Context) (*proto.Version, error) {
	return &proto.Version{
		WebrpcVersion: proto.WebRPCVersion(),
		SchemaVersion: proto.WebRPCSchemaVersion(),
		SchemaHash:    proto.WebRPCSchemaHash(),
		AppVersion:    "dev",
	}, nil
}

func (s *RPC) RuntimeStatus(ctx context.Context) (*proto.RuntimeStatus, error) {
	return &proto.RuntimeStatus{
		HealthOK:  true,
		StartTime: s.startTime,
		Uptime:    uint64(time.Since(s.startTime).Seconds()),
	}, nil
}

func (s *RPC) Clock(ctx context.Context) (time.Time, error) {
	now := time.Now()
	return now, nil
}
