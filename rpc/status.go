package rpc

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	waasauthenticator "github.com/0xsequence/waas-authenticator"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
)

func (s *RPC) Version(ctx context.Context) (*proto.Version, error) {
	return &proto.Version{
		WebrpcVersion: proto.WebRPCVersion(),
		SchemaVersion: proto.WebRPCSchemaVersion(),
		SchemaHash:    proto.WebRPCSchemaHash(),
	}, nil
}

func (s *RPC) RuntimeStatus(ctx context.Context) (*proto.RuntimeStatus, error) {
	status := &proto.RuntimeStatus{
		HealthOK:  true,
		StartTime: s.startTime,
		Uptime:    uint64(time.Now().UTC().Sub(s.startTime).Seconds()),
		Ver:       waasauthenticator.VERSION,
		PCR0:      s.measurements.PCR0,
	}
	return status, nil
}

func (s *RPC) Clock(ctx context.Context) (time.Time, error) {
	now := time.Now()
	return now, nil
}

func (s *RPC) statusHandler(w http.ResponseWriter, r *http.Request) {
	status := &proto.RuntimeStatus{
		HealthOK:  true,
		StartTime: s.startTime,
		Uptime:    uint64(time.Now().UTC().Sub(s.startTime).Seconds()),
		Ver:       waasauthenticator.VERSION,
		PCR0:      s.measurements.PCR0,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}

func (s *RPC) healthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	att := attestation.FromContext(ctx)
	if _, err := att.GenerateDataKey(ctx, s.Config.KMS.TenantKeys[0]); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}
