package enclave

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/0xsequence/nsm/request"
	"github.com/0xsequence/nsm/response"
)

func DummyProvider(_ context.Context) (Session, error) {
	return &dummySession{random: rand.Reader}, nil
}

type dummySession struct {
	random io.Reader
	closed atomic.Bool
}

func (d *dummySession) Read(p []byte) (n int, err error) {
	if d.closed.Load() {
		return 0, fmt.Errorf("session is closed")
	}
	return d.random.Read(p)
}

func (d *dummySession) Close() error {
	d.closed.Store(true)
	return nil
}

func (d *dummySession) Send(req request.Request) (response.Response, error) {
	switch req := req.(type) {
	case *request.Attestation:
		return d.handleAttestation(req)
	default:
		return response.Response{}, fmt.Errorf("unsupported request type: %T", req)
	}
}

func (d *dummySession) handleAttestation(req *request.Attestation) (response.Response, error) {
	document := []byte("DEV ONLY. NOT FOR PROD USE.")
	if len(req.Nonce) > 0 {
		document = append(document, []byte(" NONCE=")...)
		document = append(document, req.Nonce...)
	}
	if len(req.PublicKey) > 0 {
		document = append(document, []byte(" PUBKEY=")...)
		document = append(document, req.PublicKey...)
	}

	res := response.Response{
		Attestation: &response.Attestation{
			Document: document,
		},
	}
	return res, nil
}
