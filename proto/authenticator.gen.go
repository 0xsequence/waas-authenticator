// sequence-waas-authenticator v0.1.0 40d0a5540ec55ae7e7acec17d28bdfed19c9afa8
// --
// Code generated by webrpc-gen@v0.14.0-dev with golang generator. DO NOT EDIT.
//
// webrpc-gen -schema=authenticator.ridl -target=golang -pkg=proto -server -client -out=./authenticator.gen.go
package proto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
)

// WebRPC description and code-gen version
func WebRPCVersion() string {
	return "v1"
}

// Schema version of your RIDL schema
func WebRPCSchemaVersion() string {
	return "v0.1.0"
}

// Schema hash generated from your RIDL schema
func WebRPCSchemaHash() string {
	return "40d0a5540ec55ae7e7acec17d28bdfed19c9afa8"
}

//
// Types
//

type Version struct {
	WebrpcVersion string `json:"webrpcVersion"`
	SchemaVersion string `json:"schemaVersion"`
	SchemaHash    string `json:"schemaHash"`
	AppVersion    string `json:"appVersion"`
}

type RuntimeStatus struct {
	HealthOK   bool      `json:"healthOK"`
	StartTime  time.Time `json:"startTime"`
	Uptime     uint64    `json:"uptime"`
	Ver        string    `json:"ver"`
	Branch     string    `json:"branch"`
	CommitHash string    `json:"commitHash"`
}

type RegisterSessionPayload struct {
	ProjectID      uint64 `json:"projectId"`
	IDToken        string `json:"idToken"`
	SessionAddress string `json:"sessionAddress"`
	FriendlyName   string `json:"friendlyName"`
	IntentJSON     string `json:"intentJSON"`
}

type RefreshSessionPayload struct {
	SessionID string `json:"sessionId"`
}

type DropSessionPayload struct {
	SessionID     string `json:"sessionId"`
	DropSessionID string `json:"dropSessionId"`
}

type ListSessionsPayload struct {
	SessionID string `json:"sessionId"`
}

type GetAddressPayload struct {
	SessionID string `json:"sessionId"`
}

type SendIntentPayload struct {
	SessionID  string `json:"sessionId"`
	IntentJSON string `json:"intentJson"`
}

type Identity struct {
	ProjectID uint64 `json:"projectId"`
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject"`
}

type OpenIdProvider struct {
	Issuer          string  `json:"iss"`
	AuthorizedParty *string `json:"azp"`
	Audience        *string `json:"aud"`
}

type Tenant struct {
	ProjectID     uint64            `json:"projectId"`
	Version       int               `json:"version"`
	OIDCProviders []*OpenIdProvider `json:"oidcProviders"`
	UpdatedAt     time.Time         `json:"updatedAt"`
}

type TenantData struct {
	ProjectID       uint64               `json:"proj"`
	PrivateKey      string               `json:"prv"`
	ParentAddress   common.Address       `json:"addr"`
	UserSalt        hexutil.Bytes        `json:"salt"`
	SequenceContext *MiniSequenceContext `json:"seqctx"`
	UpgradeCode     string               `json:"upc"`
	WaasAccessToken string               `json:"wat"`
	OIDCProviders   []*OpenIdProvider    `json:"oidc"`
	TransportKeys   []string             `json:"transk"`
	SessionKeys     []string             `json:"sessk"`
}

type MiniSequenceContext struct {
	Factory    string `json:"factory"`
	MainModule string `json:"mainModule"`
}

type Session struct {
	ID           string         `json:"id"`
	Address      common.Address `json:"address"`
	UserID       string         `json:"userId"`
	ProjectID    uint64         `json:"projectId"`
	Issuer       string         `json:"issuer"`
	Subject      string         `json:"subject"`
	FriendlyName string         `json:"friendlyName"`
	CreatedAt    time.Time      `json:"createdAt"`
	RefreshedAt  time.Time      `json:"refreshedAt"`
	ExpiresAt    time.Time      `json:"expiresAt"`
}

type SessionData struct {
	Address   common.Address `json:"addr"`
	ProjectID uint64         `json:"proj"`
	Issuer    string         `json:"iss"`
	Subject   string         `json:"sub"`
	CreatedAt time.Time      `json:"iat"`
	ExpiresAt time.Time      `json:"exp"`
}

type WaasAuthenticator interface {
	RegisterSession(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (*Session, interface{}, error)
	ListSessions(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) ([]*Session, error)
	DropSession(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (bool, error)
	GetAddress(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (string, error)
	SendIntent(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (string, interface{}, error)
}

type WaasAuthenticatorAdmin interface {
	Version(ctx context.Context) (*Version, error)
	RuntimeStatus(ctx context.Context) (*RuntimeStatus, error)
	Clock(ctx context.Context) (time.Time, error)
	GetTenant(ctx context.Context, projectId uint64) (*Tenant, error)
	CreateTenant(ctx context.Context, projectId uint64, waasAccessToken string, oidcProviders []*OpenIdProvider) (*Tenant, string, error)
}

var WebRPCServices = map[string][]string{
	"WaasAuthenticator": {
		"RegisterSession",
		"ListSessions",
		"DropSession",
		"GetAddress",
		"SendIntent",
	},
	"WaasAuthenticatorAdmin": {
		"Version",
		"RuntimeStatus",
		"Clock",
		"GetTenant",
		"CreateTenant",
	},
}

//
// Server
//

type WebRPCServer interface {
	http.Handler
}

type waasAuthenticatorServer struct {
	WaasAuthenticator
	OnError func(r *http.Request, rpcErr *WebRPCError)
}

func NewWaasAuthenticatorServer(svc WaasAuthenticator) *waasAuthenticatorServer {
	return &waasAuthenticatorServer{
		WaasAuthenticator: svc,
	}
}

func (s *waasAuthenticatorServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		// In case of a panic, serve a HTTP 500 error and then panic.
		if rr := recover(); rr != nil {
			s.sendErrorJSON(w, r, ErrWebrpcServerPanic.WithCause(fmt.Errorf("%v", rr)))
			panic(rr)
		}
	}()

	ctx := r.Context()
	ctx = context.WithValue(ctx, HTTPResponseWriterCtxKey, w)
	ctx = context.WithValue(ctx, HTTPRequestCtxKey, r)
	ctx = context.WithValue(ctx, ServiceNameCtxKey, "WaasAuthenticator")

	var handler func(ctx context.Context, w http.ResponseWriter, r *http.Request)
	switch r.URL.Path {
	case "/rpc/WaasAuthenticator/RegisterSession":
		handler = s.serveRegisterSessionJSON
	case "/rpc/WaasAuthenticator/ListSessions":
		handler = s.serveListSessionsJSON
	case "/rpc/WaasAuthenticator/DropSession":
		handler = s.serveDropSessionJSON
	case "/rpc/WaasAuthenticator/GetAddress":
		handler = s.serveGetAddressJSON
	case "/rpc/WaasAuthenticator/SendIntent":
		handler = s.serveSendIntentJSON
	default:
		err := ErrWebrpcBadRoute.WithCause(fmt.Errorf("no handler for path %q", r.URL.Path))
		s.sendErrorJSON(w, r, err)
		return
	}

	if r.Method != "POST" {
		w.Header().Add("Allow", "POST") // RFC 9110.
		err := ErrWebrpcBadMethod.WithCause(fmt.Errorf("unsupported method %q (only POST is allowed)", r.Method))
		s.sendErrorJSON(w, r, err)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if i := strings.Index(contentType, ";"); i >= 0 {
		contentType = contentType[:i]
	}
	contentType = strings.TrimSpace(strings.ToLower(contentType))

	switch contentType {
	case "application/json":
		handler(ctx, w, r)
	default:
		err := ErrWebrpcBadRequest.WithCause(fmt.Errorf("unexpected Content-Type: %q", r.Header.Get("Content-Type")))
		s.sendErrorJSON(w, r, err)
	}
}

func (s *waasAuthenticatorServer) serveRegisterSessionJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "RegisterSession")

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to read request data: %w", err)))
		return
	}
	defer r.Body.Close()

	reqPayload := struct {
		Arg0 string `json:"encryptedPayloadKey"`
		Arg1 string `json:"payloadCiphertext"`
		Arg2 string `json:"payloadSig"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, ret1, err := s.WaasAuthenticator.RegisterSession(ctx, reqPayload.Arg0, reqPayload.Arg1, reqPayload.Arg2)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 *Session    `json:"session"`
		Ret1 interface{} `json:"data"`
	}{ret0, ret1}
	respBody, err := json.Marshal(respPayload)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to marshal json response: %w", err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

func (s *waasAuthenticatorServer) serveListSessionsJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "ListSessions")

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to read request data: %w", err)))
		return
	}
	defer r.Body.Close()

	reqPayload := struct {
		Arg0 string `json:"encryptedPayloadKey"`
		Arg1 string `json:"payloadCiphertext"`
		Arg2 string `json:"payloadSig"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, err := s.WaasAuthenticator.ListSessions(ctx, reqPayload.Arg0, reqPayload.Arg1, reqPayload.Arg2)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 []*Session `json:"sessions"`
	}{ret0}
	respBody, err := json.Marshal(respPayload)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to marshal json response: %w", err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

func (s *waasAuthenticatorServer) serveDropSessionJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "DropSession")

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to read request data: %w", err)))
		return
	}
	defer r.Body.Close()

	reqPayload := struct {
		Arg0 string `json:"encryptedPayloadKey"`
		Arg1 string `json:"payloadCiphertext"`
		Arg2 string `json:"payloadSig"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, err := s.WaasAuthenticator.DropSession(ctx, reqPayload.Arg0, reqPayload.Arg1, reqPayload.Arg2)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 bool `json:"ok"`
	}{ret0}
	respBody, err := json.Marshal(respPayload)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to marshal json response: %w", err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

func (s *waasAuthenticatorServer) serveGetAddressJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "GetAddress")

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to read request data: %w", err)))
		return
	}
	defer r.Body.Close()

	reqPayload := struct {
		Arg0 string `json:"encryptedPayloadKey"`
		Arg1 string `json:"payloadCiphertext"`
		Arg2 string `json:"payloadSig"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, err := s.WaasAuthenticator.GetAddress(ctx, reqPayload.Arg0, reqPayload.Arg1, reqPayload.Arg2)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 string `json:"address"`
	}{ret0}
	respBody, err := json.Marshal(respPayload)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to marshal json response: %w", err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

func (s *waasAuthenticatorServer) serveSendIntentJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "SendIntent")

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to read request data: %w", err)))
		return
	}
	defer r.Body.Close()

	reqPayload := struct {
		Arg0 string `json:"encryptedPayloadKey"`
		Arg1 string `json:"payloadCiphertext"`
		Arg2 string `json:"payloadSig"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, ret1, err := s.WaasAuthenticator.SendIntent(ctx, reqPayload.Arg0, reqPayload.Arg1, reqPayload.Arg2)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 string      `json:"code"`
		Ret1 interface{} `json:"data"`
	}{ret0, ret1}
	respBody, err := json.Marshal(respPayload)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to marshal json response: %w", err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

func (s *waasAuthenticatorServer) sendErrorJSON(w http.ResponseWriter, r *http.Request, rpcErr WebRPCError) {
	if s.OnError != nil {
		s.OnError(r, &rpcErr)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rpcErr.HTTPStatus)

	respBody, _ := json.Marshal(rpcErr)
	w.Write(respBody)
}

type waasAuthenticatorAdminServer struct {
	WaasAuthenticatorAdmin
	OnError func(r *http.Request, rpcErr *WebRPCError)
}

func NewWaasAuthenticatorAdminServer(svc WaasAuthenticatorAdmin) *waasAuthenticatorAdminServer {
	return &waasAuthenticatorAdminServer{
		WaasAuthenticatorAdmin: svc,
	}
}

func (s *waasAuthenticatorAdminServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		// In case of a panic, serve a HTTP 500 error and then panic.
		if rr := recover(); rr != nil {
			s.sendErrorJSON(w, r, ErrWebrpcServerPanic.WithCause(fmt.Errorf("%v", rr)))
			panic(rr)
		}
	}()

	ctx := r.Context()
	ctx = context.WithValue(ctx, HTTPResponseWriterCtxKey, w)
	ctx = context.WithValue(ctx, HTTPRequestCtxKey, r)
	ctx = context.WithValue(ctx, ServiceNameCtxKey, "WaasAuthenticatorAdmin")

	var handler func(ctx context.Context, w http.ResponseWriter, r *http.Request)
	switch r.URL.Path {
	case "/rpc/WaasAuthenticatorAdmin/Version":
		handler = s.serveVersionJSON
	case "/rpc/WaasAuthenticatorAdmin/RuntimeStatus":
		handler = s.serveRuntimeStatusJSON
	case "/rpc/WaasAuthenticatorAdmin/Clock":
		handler = s.serveClockJSON
	case "/rpc/WaasAuthenticatorAdmin/GetTenant":
		handler = s.serveGetTenantJSON
	case "/rpc/WaasAuthenticatorAdmin/CreateTenant":
		handler = s.serveCreateTenantJSON
	default:
		err := ErrWebrpcBadRoute.WithCause(fmt.Errorf("no handler for path %q", r.URL.Path))
		s.sendErrorJSON(w, r, err)
		return
	}

	if r.Method != "POST" {
		w.Header().Add("Allow", "POST") // RFC 9110.
		err := ErrWebrpcBadMethod.WithCause(fmt.Errorf("unsupported method %q (only POST is allowed)", r.Method))
		s.sendErrorJSON(w, r, err)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if i := strings.Index(contentType, ";"); i >= 0 {
		contentType = contentType[:i]
	}
	contentType = strings.TrimSpace(strings.ToLower(contentType))

	switch contentType {
	case "application/json":
		handler(ctx, w, r)
	default:
		err := ErrWebrpcBadRequest.WithCause(fmt.Errorf("unexpected Content-Type: %q", r.Header.Get("Content-Type")))
		s.sendErrorJSON(w, r, err)
	}
}

func (s *waasAuthenticatorAdminServer) serveVersionJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "Version")

	// Call service method implementation.
	ret0, err := s.WaasAuthenticatorAdmin.Version(ctx)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 *Version `json:"version"`
	}{ret0}
	respBody, err := json.Marshal(respPayload)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to marshal json response: %w", err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

func (s *waasAuthenticatorAdminServer) serveRuntimeStatusJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "RuntimeStatus")

	// Call service method implementation.
	ret0, err := s.WaasAuthenticatorAdmin.RuntimeStatus(ctx)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 *RuntimeStatus `json:"status"`
	}{ret0}
	respBody, err := json.Marshal(respPayload)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to marshal json response: %w", err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

func (s *waasAuthenticatorAdminServer) serveClockJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "Clock")

	// Call service method implementation.
	ret0, err := s.WaasAuthenticatorAdmin.Clock(ctx)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 time.Time `json:"serverTime"`
	}{ret0}
	respBody, err := json.Marshal(respPayload)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to marshal json response: %w", err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

func (s *waasAuthenticatorAdminServer) serveGetTenantJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "GetTenant")

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to read request data: %w", err)))
		return
	}
	defer r.Body.Close()

	reqPayload := struct {
		Arg0 uint64 `json:"projectId"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, err := s.WaasAuthenticatorAdmin.GetTenant(ctx, reqPayload.Arg0)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 *Tenant `json:"tenant"`
	}{ret0}
	respBody, err := json.Marshal(respPayload)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to marshal json response: %w", err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

func (s *waasAuthenticatorAdminServer) serveCreateTenantJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "CreateTenant")

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to read request data: %w", err)))
		return
	}
	defer r.Body.Close()

	reqPayload := struct {
		Arg0 uint64            `json:"projectId"`
		Arg1 string            `json:"waasAccessToken"`
		Arg2 []*OpenIdProvider `json:"oidcProviders"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, ret1, err := s.WaasAuthenticatorAdmin.CreateTenant(ctx, reqPayload.Arg0, reqPayload.Arg1, reqPayload.Arg2)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 *Tenant `json:"tenant"`
		Ret1 string  `json:"upgradeCode"`
	}{ret0, ret1}
	respBody, err := json.Marshal(respPayload)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to marshal json response: %w", err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

func (s *waasAuthenticatorAdminServer) sendErrorJSON(w http.ResponseWriter, r *http.Request, rpcErr WebRPCError) {
	if s.OnError != nil {
		s.OnError(r, &rpcErr)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rpcErr.HTTPStatus)

	respBody, _ := json.Marshal(rpcErr)
	w.Write(respBody)
}
func RespondWithError(w http.ResponseWriter, err error) {
	rpcErr, ok := err.(WebRPCError)
	if !ok {
		rpcErr = ErrWebrpcEndpoint.WithCause(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rpcErr.HTTPStatus)

	respBody, _ := json.Marshal(rpcErr)
	w.Write(respBody)
}

//
// Client
//

const WaasAuthenticatorPathPrefix = "/rpc/WaasAuthenticator/"
const WaasAuthenticatorAdminPathPrefix = "/rpc/WaasAuthenticatorAdmin/"

type waasAuthenticatorClient struct {
	client HTTPClient
	urls   [5]string
}

func NewWaasAuthenticatorClient(addr string, client HTTPClient) WaasAuthenticator {
	prefix := urlBase(addr) + WaasAuthenticatorPathPrefix
	urls := [5]string{
		prefix + "RegisterSession",
		prefix + "ListSessions",
		prefix + "DropSession",
		prefix + "GetAddress",
		prefix + "SendIntent",
	}
	return &waasAuthenticatorClient{
		client: client,
		urls:   urls,
	}
}

func (c *waasAuthenticatorClient) RegisterSession(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (*Session, interface{}, error) {
	in := struct {
		Arg0 string `json:"encryptedPayloadKey"`
		Arg1 string `json:"payloadCiphertext"`
		Arg2 string `json:"payloadSig"`
	}{encryptedPayloadKey, payloadCiphertext, payloadSig}
	out := struct {
		Ret0 *Session    `json:"session"`
		Ret1 interface{} `json:"data"`
	}{}

	err := doJSONRequest(ctx, c.client, c.urls[0], in, &out)
	return out.Ret0, out.Ret1, err
}

func (c *waasAuthenticatorClient) ListSessions(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) ([]*Session, error) {
	in := struct {
		Arg0 string `json:"encryptedPayloadKey"`
		Arg1 string `json:"payloadCiphertext"`
		Arg2 string `json:"payloadSig"`
	}{encryptedPayloadKey, payloadCiphertext, payloadSig}
	out := struct {
		Ret0 []*Session `json:"sessions"`
	}{}

	err := doJSONRequest(ctx, c.client, c.urls[1], in, &out)
	return out.Ret0, err
}

func (c *waasAuthenticatorClient) DropSession(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (bool, error) {
	in := struct {
		Arg0 string `json:"encryptedPayloadKey"`
		Arg1 string `json:"payloadCiphertext"`
		Arg2 string `json:"payloadSig"`
	}{encryptedPayloadKey, payloadCiphertext, payloadSig}
	out := struct {
		Ret0 bool `json:"ok"`
	}{}

	err := doJSONRequest(ctx, c.client, c.urls[2], in, &out)
	return out.Ret0, err
}

func (c *waasAuthenticatorClient) GetAddress(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (string, error) {
	in := struct {
		Arg0 string `json:"encryptedPayloadKey"`
		Arg1 string `json:"payloadCiphertext"`
		Arg2 string `json:"payloadSig"`
	}{encryptedPayloadKey, payloadCiphertext, payloadSig}
	out := struct {
		Ret0 string `json:"address"`
	}{}

	err := doJSONRequest(ctx, c.client, c.urls[3], in, &out)
	return out.Ret0, err
}

func (c *waasAuthenticatorClient) SendIntent(ctx context.Context, encryptedPayloadKey string, payloadCiphertext string, payloadSig string) (string, interface{}, error) {
	in := struct {
		Arg0 string `json:"encryptedPayloadKey"`
		Arg1 string `json:"payloadCiphertext"`
		Arg2 string `json:"payloadSig"`
	}{encryptedPayloadKey, payloadCiphertext, payloadSig}
	out := struct {
		Ret0 string      `json:"code"`
		Ret1 interface{} `json:"data"`
	}{}

	err := doJSONRequest(ctx, c.client, c.urls[4], in, &out)
	return out.Ret0, out.Ret1, err
}

type waasAuthenticatorAdminClient struct {
	client HTTPClient
	urls   [5]string
}

func NewWaasAuthenticatorAdminClient(addr string, client HTTPClient) WaasAuthenticatorAdmin {
	prefix := urlBase(addr) + WaasAuthenticatorAdminPathPrefix
	urls := [5]string{
		prefix + "Version",
		prefix + "RuntimeStatus",
		prefix + "Clock",
		prefix + "GetTenant",
		prefix + "CreateTenant",
	}
	return &waasAuthenticatorAdminClient{
		client: client,
		urls:   urls,
	}
}

func (c *waasAuthenticatorAdminClient) Version(ctx context.Context) (*Version, error) {
	out := struct {
		Ret0 *Version `json:"version"`
	}{}

	err := doJSONRequest(ctx, c.client, c.urls[0], nil, &out)
	return out.Ret0, err
}

func (c *waasAuthenticatorAdminClient) RuntimeStatus(ctx context.Context) (*RuntimeStatus, error) {
	out := struct {
		Ret0 *RuntimeStatus `json:"status"`
	}{}

	err := doJSONRequest(ctx, c.client, c.urls[1], nil, &out)
	return out.Ret0, err
}

func (c *waasAuthenticatorAdminClient) Clock(ctx context.Context) (time.Time, error) {
	out := struct {
		Ret0 time.Time `json:"serverTime"`
	}{}

	err := doJSONRequest(ctx, c.client, c.urls[2], nil, &out)
	return out.Ret0, err
}

func (c *waasAuthenticatorAdminClient) GetTenant(ctx context.Context, projectId uint64) (*Tenant, error) {
	in := struct {
		Arg0 uint64 `json:"projectId"`
	}{projectId}
	out := struct {
		Ret0 *Tenant `json:"tenant"`
	}{}

	err := doJSONRequest(ctx, c.client, c.urls[3], in, &out)
	return out.Ret0, err
}

func (c *waasAuthenticatorAdminClient) CreateTenant(ctx context.Context, projectId uint64, waasAccessToken string, oidcProviders []*OpenIdProvider) (*Tenant, string, error) {
	in := struct {
		Arg0 uint64            `json:"projectId"`
		Arg1 string            `json:"waasAccessToken"`
		Arg2 []*OpenIdProvider `json:"oidcProviders"`
	}{projectId, waasAccessToken, oidcProviders}
	out := struct {
		Ret0 *Tenant `json:"tenant"`
		Ret1 string  `json:"upgradeCode"`
	}{}

	err := doJSONRequest(ctx, c.client, c.urls[4], in, &out)
	return out.Ret0, out.Ret1, err
}

// HTTPClient is the interface used by generated clients to send HTTP requests.
// It is fulfilled by *(net/http).Client, which is sufficient for most users.
// Users can provide their own implementation for special retry policies.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// urlBase helps ensure that addr specifies a scheme. If it is unparsable
// as a URL, it returns addr unchanged.
func urlBase(addr string) string {
	// If the addr specifies a scheme, use it. If not, default to
	// http. If url.Parse fails on it, return it unchanged.
	url, err := url.Parse(addr)
	if err != nil {
		return addr
	}
	if url.Scheme == "" {
		url.Scheme = "http"
	}
	return url.String()
}

// newRequest makes an http.Request from a client, adding common headers.
func newRequest(ctx context.Context, url string, reqBody io.Reader, contentType string) (*http.Request, error) {
	req, err := http.NewRequest("POST", url, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", contentType)
	req.Header.Set("Content-Type", contentType)
	if headers, ok := HTTPRequestHeaders(ctx); ok {
		for k := range headers {
			for _, v := range headers[k] {
				req.Header.Add(k, v)
			}
		}
	}
	return req, nil
}

// doJSONRequest is common code to make a request to the remote service.
func doJSONRequest(ctx context.Context, client HTTPClient, url string, in, out interface{}) error {
	reqBody, err := json.Marshal(in)
	if err != nil {
		return ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to marshal JSON body: %w", err))
	}
	if err = ctx.Err(); err != nil {
		return ErrWebrpcRequestFailed.WithCause(fmt.Errorf("aborted because context was done: %w", err))
	}

	req, err := newRequest(ctx, url, bytes.NewBuffer(reqBody), "application/json")
	if err != nil {
		return ErrWebrpcRequestFailed.WithCause(fmt.Errorf("could not build request: %w", err))
	}
	resp, err := client.Do(req)
	if err != nil {
		return ErrWebrpcRequestFailed.WithCause(err)
	}

	defer func() {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}()

	if err = ctx.Err(); err != nil {
		return ErrWebrpcRequestFailed.WithCause(fmt.Errorf("aborted because context was done: %w", err))
	}

	if resp.StatusCode != 200 {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to read server error response body: %w", err))
		}

		var rpcErr WebRPCError
		if err := json.Unmarshal(respBody, &rpcErr); err != nil {
			return ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to unmarshal server error: %w", err))
		}
		if rpcErr.Cause != "" {
			rpcErr.cause = errors.New(rpcErr.Cause)
		}
		return rpcErr
	}

	if out != nil {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to read response body: %w", err))
		}

		err = json.Unmarshal(respBody, &out)
		if err != nil {
			return ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to unmarshal JSON response body: %w", err))
		}
	}

	return nil
}

func WithHTTPRequestHeaders(ctx context.Context, h http.Header) (context.Context, error) {
	if _, ok := h["Accept"]; ok {
		return nil, errors.New("provided header cannot set Accept")
	}
	if _, ok := h["Content-Type"]; ok {
		return nil, errors.New("provided header cannot set Content-Type")
	}

	copied := make(http.Header, len(h))
	for k, vv := range h {
		if vv == nil {
			copied[k] = nil
			continue
		}
		copied[k] = make([]string, len(vv))
		copy(copied[k], vv)
	}

	return context.WithValue(ctx, HTTPClientRequestHeadersCtxKey, copied), nil
}

func HTTPRequestHeaders(ctx context.Context) (http.Header, bool) {
	h, ok := ctx.Value(HTTPClientRequestHeadersCtxKey).(http.Header)
	return h, ok
}

//
// Helpers
//

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "webrpc context value " + k.name
}

var (
	HTTPClientRequestHeadersCtxKey = &contextKey{"HTTPClientRequestHeaders"}
	HTTPResponseWriterCtxKey       = &contextKey{"HTTPResponseWriter"}

	HTTPRequestCtxKey = &contextKey{"HTTPRequest"}

	ServiceNameCtxKey = &contextKey{"ServiceName"}

	MethodNameCtxKey = &contextKey{"MethodName"}
)

func ServiceNameFromContext(ctx context.Context) string {
	service, _ := ctx.Value(ServiceNameCtxKey).(string)
	return service
}

func MethodNameFromContext(ctx context.Context) string {
	method, _ := ctx.Value(MethodNameCtxKey).(string)
	return method
}

func RequestFromContext(ctx context.Context) *http.Request {
	r, _ := ctx.Value(HTTPRequestCtxKey).(*http.Request)
	return r
}
func ResponseWriterFromContext(ctx context.Context) http.ResponseWriter {
	w, _ := ctx.Value(HTTPResponseWriterCtxKey).(http.ResponseWriter)
	return w
}

//
// Errors
//

type WebRPCError struct {
	Name       string `json:"error"`
	Code       int    `json:"code"`
	Message    string `json:"msg"`
	Cause      string `json:"cause,omitempty"`
	HTTPStatus int    `json:"status"`
	cause      error
}

var _ error = WebRPCError{}

func (e WebRPCError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s %d: %s: %v", e.Name, e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("%s %d: %s", e.Name, e.Code, e.Message)
}

func (e WebRPCError) Is(target error) bool {
	if rpcErr, ok := target.(WebRPCError); ok {
		return rpcErr.Code == e.Code
	}
	return errors.Is(e.cause, target)
}

func (e WebRPCError) Unwrap() error {
	return e.cause
}

func (e WebRPCError) WithCause(cause error) WebRPCError {
	err := e
	err.cause = cause
	err.Cause = cause.Error()
	return err
}

// Deprecated: Use .WithCause() method on WebRPCError.
func ErrorWithCause(rpcErr WebRPCError, cause error) WebRPCError {
	return rpcErr.WithCause(cause)
}

// Webrpc errors
var (
	ErrWebrpcEndpoint      = WebRPCError{Code: 0, Name: "WebrpcEndpoint", Message: "endpoint error", HTTPStatus: 400}
	ErrWebrpcRequestFailed = WebRPCError{Code: -1, Name: "WebrpcRequestFailed", Message: "request failed", HTTPStatus: 400}
	ErrWebrpcBadRoute      = WebRPCError{Code: -2, Name: "WebrpcBadRoute", Message: "bad route", HTTPStatus: 404}
	ErrWebrpcBadMethod     = WebRPCError{Code: -3, Name: "WebrpcBadMethod", Message: "bad method", HTTPStatus: 405}
	ErrWebrpcBadRequest    = WebRPCError{Code: -4, Name: "WebrpcBadRequest", Message: "bad request", HTTPStatus: 400}
	ErrWebrpcBadResponse   = WebRPCError{Code: -5, Name: "WebrpcBadResponse", Message: "bad response", HTTPStatus: 500}
	ErrWebrpcServerPanic   = WebRPCError{Code: -6, Name: "WebrpcServerPanic", Message: "server panic", HTTPStatus: 500}
	ErrWebrpcInternalError = WebRPCError{Code: -7, Name: "WebrpcInternalError", Message: "internal error", HTTPStatus: 500}
)

// Schema errors
var (
	ErrUnauthorized = WebRPCError{Code: 1000, Name: "Unauthorized", Message: "Unauthorized access", HTTPStatus: 401}
)
