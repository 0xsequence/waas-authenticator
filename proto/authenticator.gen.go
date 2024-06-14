// sequence-waas-authenticator v0.1.0 e104837405deeba9b67f85f8db3de21be7189f42
// --
// Code generated by webrpc-gen@v0.18.7 with golang generator. DO NOT EDIT.
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
	"github.com/goware/validation"
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
	return "e104837405deeba9b67f85f8db3de21be7189f42"
}

//
// Common types
//

type IntentName string

const (
	IntentName_initiateAuth          IntentName = "initiateAuth"
	IntentName_openSession           IntentName = "openSession"
	IntentName_closeSession          IntentName = "closeSession"
	IntentName_validateSession       IntentName = "validateSession"
	IntentName_finishValidateSession IntentName = "finishValidateSession"
	IntentName_listSessions          IntentName = "listSessions"
	IntentName_getSession            IntentName = "getSession"
	IntentName_sessionAuthProof      IntentName = "sessionAuthProof"
	IntentName_feeOptions            IntentName = "feeOptions"
	IntentName_signMessage           IntentName = "signMessage"
	IntentName_sendTransaction       IntentName = "sendTransaction"
	IntentName_getTransactionReceipt IntentName = "getTransactionReceipt"
	IntentName_federateAccount       IntentName = "federateAccount"
	IntentName_removeAccount         IntentName = "removeAccount"
	IntentName_listAccounts          IntentName = "listAccounts"
	IntentName_getIdToken            IntentName = "getIdToken"
)

func (x IntentName) MarshalText() ([]byte, error) {
	return []byte(x), nil
}

func (x *IntentName) UnmarshalText(b []byte) error {
	*x = IntentName(string(b))
	return nil
}

func (x *IntentName) Is(values ...IntentName) bool {
	if x == nil {
		return false
	}
	for _, v := range values {
		if *x == v {
			return true
		}
	}
	return false
}

type IntentResponseCode string

const (
	IntentResponseCode_authInitiated      IntentResponseCode = "authInitiated"
	IntentResponseCode_sessionOpened      IntentResponseCode = "sessionOpened"
	IntentResponseCode_sessionClosed      IntentResponseCode = "sessionClosed"
	IntentResponseCode_sessionList        IntentResponseCode = "sessionList"
	IntentResponseCode_validationRequired IntentResponseCode = "validationRequired"
	IntentResponseCode_validationStarted  IntentResponseCode = "validationStarted"
	IntentResponseCode_validationFinished IntentResponseCode = "validationFinished"
	IntentResponseCode_sessionAuthProof   IntentResponseCode = "sessionAuthProof"
	IntentResponseCode_signedMessage      IntentResponseCode = "signedMessage"
	IntentResponseCode_feeOptions         IntentResponseCode = "feeOptions"
	IntentResponseCode_transactionReceipt IntentResponseCode = "transactionReceipt"
	IntentResponseCode_transactionFailed  IntentResponseCode = "transactionFailed"
	IntentResponseCode_getSessionResponse IntentResponseCode = "getSessionResponse"
	IntentResponseCode_accountList        IntentResponseCode = "accountList"
	IntentResponseCode_accountFederated   IntentResponseCode = "accountFederated"
	IntentResponseCode_accountRemoved     IntentResponseCode = "accountRemoved"
	IntentResponseCode_idToken            IntentResponseCode = "idToken"
)

func (x IntentResponseCode) MarshalText() ([]byte, error) {
	return []byte(x), nil
}

func (x *IntentResponseCode) UnmarshalText(b []byte) error {
	*x = IntentResponseCode(string(b))
	return nil
}

func (x *IntentResponseCode) Is(values ...IntentResponseCode) bool {
	if x == nil {
		return false
	}
	for _, v := range values {
		if *x == v {
			return true
		}
	}
	return false
}

type IdentityType string

const (
	IdentityType_None  IdentityType = "None"
	IdentityType_Guest IdentityType = "Guest"
	IdentityType_OIDC  IdentityType = "OIDC"
	IdentityType_Email IdentityType = "Email"
)

func (x IdentityType) MarshalText() ([]byte, error) {
	return []byte(x), nil
}

func (x *IdentityType) UnmarshalText(b []byte) error {
	*x = IdentityType(string(b))
	return nil
}

func (x *IdentityType) Is(values ...IdentityType) bool {
	if x == nil {
		return false
	}
	for _, v := range values {
		if *x == v {
			return true
		}
	}
	return false
}

type Intent struct {
	Version    string       `json:"version"`
	Name       IntentName   `json:"name"`
	ExpiresAt  uint64       `json:"expiresAt"`
	IssuedAt   uint64       `json:"issuedAt"`
	Data       interface{}  `json:"data"`
	Signatures []*Signature `json:"signatures,omitempty"`
}

type Signature struct {
	SessionID string `json:"sessionId"`
	Signature string `json:"signature"`
}

type IntentResponse struct {
	Code IntentResponseCode `json:"code"`
	Data interface{}        `json:"data"`
}

type Version struct {
	WebrpcVersion string `json:"webrpcVersion"`
	SchemaVersion string `json:"schemaVersion"`
	SchemaHash    string `json:"schemaHash"`
	AppVersion    string `json:"appVersion"`
}

type RuntimeStatus struct {
	// overall status, true/false
	HealthOK  bool      `json:"healthOK"`
	StartTime time.Time `json:"startTime"`
	Uptime    uint64    `json:"uptime"`
	Ver       string    `json:"ver"`
	PCR0      string    `json:"pcr0"`
}

type Chain struct {
	Id        uint64 `json:"id"`
	Name      string `json:"name"`
	IsEnabled bool   `json:"isEnabled"`
}

type Identity struct {
	Type    IdentityType `json:"type"`
	Issuer  string       `json:"iss"`
	Subject string       `json:"sub"`
	Email   string       `json:"email,omitempty"`
}

type OpenIdProvider struct {
	Issuer   string   `json:"iss"`
	Audience []string `json:"aud"`
}

type AuthEmailConfig struct {
	Enabled bool `json:"enabled"`
}

type AuthGuestConfig struct {
	Enabled bool `json:"enabled"`
}

type AuthConfig struct {
	Email AuthEmailConfig `json:"email,omitempty"`
	Guest AuthGuestConfig `json:"guest,omitempty"`
}

type Tenant struct {
	ProjectID      uint64             `json:"projectId"`
	Version        int                `json:"version"`
	OIDCProviders  []*OpenIdProvider  `json:"oidcProviders"`
	AllowedOrigins validation.Origins `json:"allowedOrigins"`
	UpdatedAt      time.Time          `json:"updatedAt"`
}

type TenantData struct {
	ProjectID       uint64               `json:"projectId"`
	PrivateKey      string               `json:"privateKey"`
	ParentAddress   common.Address       `json:"parentAddress"`
	UserSalt        hexutil.Bytes        `json:"userSalt"`
	SequenceContext *MiniSequenceContext `json:"sequenceContext"`
	UpgradeCode     string               `json:"upgradeCode"`
	WaasAccessToken string               `json:"waasAccessToken"`
	AuthConfig      AuthConfig           `json:"authConfig"`
	OIDCProviders   []*OpenIdProvider    `json:"oidcProviders"`
	KMSKeys         []string             `json:"kmsKeys"`
	AllowedOrigins  validation.Origins   `json:"allowedOrigins"`
}

type MiniSequenceContext struct {
	Factory    string `json:"factory"`
	MainModule string `json:"mainModule"`
}

type AccountData struct {
	ProjectID uint64    `json:"projectId"`
	UserID    string    `json:"userId"`
	Identity  string    `json:"identity"`
	CreatedAt time.Time `json:"createdAt"`
}

type Session struct {
	ID           string    `json:"id"`
	ProjectID    uint64    `json:"projectId"`
	UserID       string    `json:"userId"`
	Identity     Identity  `json:"identity"`
	FriendlyName string    `json:"friendlyName"`
	CreatedAt    time.Time `json:"createdAt"`
	RefreshedAt  time.Time `json:"refreshedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type SessionData struct {
	ID        string    `json:"id"`
	ProjectID uint64    `json:"projectId"`
	UserID    string    `json:"userId"`
	Identity  string    `json:"identity"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type VerificationContext struct {
	ProjectID     uint64       `json:"projectId"`
	SessionID     string       `json:"sessionId"`
	IdentityType  IdentityType `json:"identityType"`
	Verifier      string       `json:"verifier"`
	Challenge     *string      `json:"challenge"`
	Answer        *string      `json:"answer"`
	Attempts      int          `json:"attempts"`
	LastAttemptAt *time.Time   `json:"lastAttemptAt"`
	ExpiresAt     time.Time    `json:"expiresAt"`
}

var WebRPCServices = map[string][]string{
	"WaasAuthenticator": {
		"RegisterSession",
		"SendIntent",
		"ChainList",
	},
	"WaasAuthenticatorAdmin": {
		"Version",
		"RuntimeStatus",
		"Clock",
		"GetTenant",
		"CreateTenant",
		"UpdateTenant",
	},
}

//
// Server types
//

type WaasAuthenticator interface {
	RegisterSession(ctx context.Context, intent *Intent, friendlyName string) (*Session, *IntentResponse, error)
	SendIntent(ctx context.Context, intent *Intent) (*IntentResponse, error)
	ChainList(ctx context.Context) ([]*Chain, error)
}

type WaasAuthenticatorAdmin interface {
	Version(ctx context.Context) (*Version, error)
	RuntimeStatus(ctx context.Context) (*RuntimeStatus, error)
	Clock(ctx context.Context) (time.Time, error)
	GetTenant(ctx context.Context, projectId uint64) (*Tenant, error)
	CreateTenant(ctx context.Context, projectId uint64, waasAccessToken string, authConfig *AuthConfig, oidcProviders []*OpenIdProvider, allowedOrigins []string, password *string) (*Tenant, string, error)
	UpdateTenant(ctx context.Context, projectId uint64, upgradeCode string, authConfig *AuthConfig, oidcProviders []*OpenIdProvider, allowedOrigins []string) (*Tenant, error)
}

//
// Client types
//

type WaasAuthenticatorClient interface {
	RegisterSession(ctx context.Context, intent *Intent, friendlyName string) (*Session, *IntentResponse, error)
	SendIntent(ctx context.Context, intent *Intent) (*IntentResponse, error)
	ChainList(ctx context.Context) ([]*Chain, error)
}

type WaasAuthenticatorAdminClient interface {
	Version(ctx context.Context) (*Version, error)
	RuntimeStatus(ctx context.Context) (*RuntimeStatus, error)
	Clock(ctx context.Context) (time.Time, error)
	GetTenant(ctx context.Context, projectId uint64) (*Tenant, error)
	CreateTenant(ctx context.Context, projectId uint64, waasAccessToken string, authConfig *AuthConfig, oidcProviders []*OpenIdProvider, allowedOrigins []string, password *string) (*Tenant, string, error)
	UpdateTenant(ctx context.Context, projectId uint64, upgradeCode string, authConfig *AuthConfig, oidcProviders []*OpenIdProvider, allowedOrigins []string) (*Tenant, error)
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
	case "/rpc/WaasAuthenticator/SendIntent":
		handler = s.serveSendIntentJSON
	case "/rpc/WaasAuthenticator/ChainList":
		handler = s.serveChainListJSON
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
		Arg0 *Intent `json:"intent"`
		Arg1 string  `json:"friendlyName"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, ret1, err := s.WaasAuthenticator.RegisterSession(ctx, reqPayload.Arg0, reqPayload.Arg1)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 *Session        `json:"session"`
		Ret1 *IntentResponse `json:"response"`
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

func (s *waasAuthenticatorServer) serveSendIntentJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "SendIntent")

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to read request data: %w", err)))
		return
	}
	defer r.Body.Close()

	reqPayload := struct {
		Arg0 *Intent `json:"intent"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, err := s.WaasAuthenticator.SendIntent(ctx, reqPayload.Arg0)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 *IntentResponse `json:"response"`
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

func (s *waasAuthenticatorServer) serveChainListJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "ChainList")

	// Call service method implementation.
	ret0, err := s.WaasAuthenticator.ChainList(ctx)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 []*Chain `json:"chains"`
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
	case "/rpc/WaasAuthenticatorAdmin/UpdateTenant":
		handler = s.serveUpdateTenantJSON
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
		Arg2 *AuthConfig       `json:"authConfig"`
		Arg3 []*OpenIdProvider `json:"oidcProviders"`
		Arg4 []string          `json:"allowedOrigins"`
		Arg5 *string           `json:"password"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, ret1, err := s.WaasAuthenticatorAdmin.CreateTenant(ctx, reqPayload.Arg0, reqPayload.Arg1, reqPayload.Arg2, reqPayload.Arg3, reqPayload.Arg4, reqPayload.Arg5)
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

func (s *waasAuthenticatorAdminServer) serveUpdateTenantJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "UpdateTenant")

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to read request data: %w", err)))
		return
	}
	defer r.Body.Close()

	reqPayload := struct {
		Arg0 uint64            `json:"projectId"`
		Arg1 string            `json:"upgradeCode"`
		Arg2 *AuthConfig       `json:"authConfig"`
		Arg3 []*OpenIdProvider `json:"oidcProviders"`
		Arg4 []string          `json:"allowedOrigins"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, err := s.WaasAuthenticatorAdmin.UpdateTenant(ctx, reqPayload.Arg0, reqPayload.Arg1, reqPayload.Arg2, reqPayload.Arg3, reqPayload.Arg4)
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
	urls   [3]string
}

func NewWaasAuthenticatorClient(addr string, client HTTPClient) WaasAuthenticatorClient {
	prefix := urlBase(addr) + WaasAuthenticatorPathPrefix
	urls := [3]string{
		prefix + "RegisterSession",
		prefix + "SendIntent",
		prefix + "ChainList",
	}
	return &waasAuthenticatorClient{
		client: client,
		urls:   urls,
	}
}

func (c *waasAuthenticatorClient) RegisterSession(ctx context.Context, intent *Intent, friendlyName string) (*Session, *IntentResponse, error) {
	in := struct {
		Arg0 *Intent `json:"intent"`
		Arg1 string  `json:"friendlyName"`
	}{intent, friendlyName}
	out := struct {
		Ret0 *Session        `json:"session"`
		Ret1 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[0], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, out.Ret1, err
}

func (c *waasAuthenticatorClient) SendIntent(ctx context.Context, intent *Intent) (*IntentResponse, error) {
	in := struct {
		Arg0 *Intent `json:"intent"`
	}{intent}
	out := struct {
		Ret0 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[1], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waasAuthenticatorClient) ChainList(ctx context.Context) ([]*Chain, error) {
	out := struct {
		Ret0 []*Chain `json:"chains"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[2], nil, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

type waasAuthenticatorAdminClient struct {
	client HTTPClient
	urls   [6]string
}

func NewWaasAuthenticatorAdminClient(addr string, client HTTPClient) WaasAuthenticatorAdminClient {
	prefix := urlBase(addr) + WaasAuthenticatorAdminPathPrefix
	urls := [6]string{
		prefix + "Version",
		prefix + "RuntimeStatus",
		prefix + "Clock",
		prefix + "GetTenant",
		prefix + "CreateTenant",
		prefix + "UpdateTenant",
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

	resp, err := doHTTPRequest(ctx, c.client, c.urls[0], nil, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waasAuthenticatorAdminClient) RuntimeStatus(ctx context.Context) (*RuntimeStatus, error) {
	out := struct {
		Ret0 *RuntimeStatus `json:"status"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[1], nil, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waasAuthenticatorAdminClient) Clock(ctx context.Context) (time.Time, error) {
	out := struct {
		Ret0 time.Time `json:"serverTime"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[2], nil, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waasAuthenticatorAdminClient) GetTenant(ctx context.Context, projectId uint64) (*Tenant, error) {
	in := struct {
		Arg0 uint64 `json:"projectId"`
	}{projectId}
	out := struct {
		Ret0 *Tenant `json:"tenant"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[3], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waasAuthenticatorAdminClient) CreateTenant(ctx context.Context, projectId uint64, waasAccessToken string, authConfig *AuthConfig, oidcProviders []*OpenIdProvider, allowedOrigins []string, password *string) (*Tenant, string, error) {
	in := struct {
		Arg0 uint64            `json:"projectId"`
		Arg1 string            `json:"waasAccessToken"`
		Arg2 *AuthConfig       `json:"authConfig"`
		Arg3 []*OpenIdProvider `json:"oidcProviders"`
		Arg4 []string          `json:"allowedOrigins"`
		Arg5 *string           `json:"password"`
	}{projectId, waasAccessToken, authConfig, oidcProviders, allowedOrigins, password}
	out := struct {
		Ret0 *Tenant `json:"tenant"`
		Ret1 string  `json:"upgradeCode"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[4], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, out.Ret1, err
}

func (c *waasAuthenticatorAdminClient) UpdateTenant(ctx context.Context, projectId uint64, upgradeCode string, authConfig *AuthConfig, oidcProviders []*OpenIdProvider, allowedOrigins []string) (*Tenant, error) {
	in := struct {
		Arg0 uint64            `json:"projectId"`
		Arg1 string            `json:"upgradeCode"`
		Arg2 *AuthConfig       `json:"authConfig"`
		Arg3 []*OpenIdProvider `json:"oidcProviders"`
		Arg4 []string          `json:"allowedOrigins"`
	}{projectId, upgradeCode, authConfig, oidcProviders, allowedOrigins}
	out := struct {
		Ret0 *Tenant `json:"tenant"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[5], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
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
	req, err := http.NewRequestWithContext(ctx, "POST", url, reqBody)
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

// doHTTPRequest is common code to make a request to the remote service.
func doHTTPRequest(ctx context.Context, client HTTPClient, url string, in, out interface{}) (*http.Response, error) {
	reqBody, err := json.Marshal(in)
	if err != nil {
		return nil, ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to marshal JSON body: %w", err))
	}
	if err = ctx.Err(); err != nil {
		return nil, ErrWebrpcRequestFailed.WithCause(fmt.Errorf("aborted because context was done: %w", err))
	}

	req, err := newRequest(ctx, url, bytes.NewBuffer(reqBody), "application/json")
	if err != nil {
		return nil, ErrWebrpcRequestFailed.WithCause(fmt.Errorf("could not build request: %w", err))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrWebrpcRequestFailed.WithCause(err)
	}

	if resp.StatusCode != 200 {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to read server error response body: %w", err))
		}

		var rpcErr WebRPCError
		if err := json.Unmarshal(respBody, &rpcErr); err != nil {
			return nil, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to unmarshal server error: %w", err))
		}
		if rpcErr.Cause != "" {
			rpcErr.cause = errors.New(rpcErr.Cause)
		}
		return nil, rpcErr
	}

	if out != nil {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to read response body: %w", err))
		}

		err = json.Unmarshal(respBody, &out)
		if err != nil {
			return nil, ErrWebrpcBadResponse.WithCause(fmt.Errorf("failed to unmarshal JSON response body: %w", err))
		}
	}

	return resp, nil
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
	if target == nil {
		return false
	}
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

func (e WebRPCError) WithCausef(format string, args ...interface{}) WebRPCError {
	cause := fmt.Errorf(format, args...)
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
	ErrWebrpcEndpoint           = WebRPCError{Code: 0, Name: "WebrpcEndpoint", Message: "endpoint error", HTTPStatus: 400}
	ErrWebrpcRequestFailed      = WebRPCError{Code: -1, Name: "WebrpcRequestFailed", Message: "request failed", HTTPStatus: 400}
	ErrWebrpcBadRoute           = WebRPCError{Code: -2, Name: "WebrpcBadRoute", Message: "bad route", HTTPStatus: 404}
	ErrWebrpcBadMethod          = WebRPCError{Code: -3, Name: "WebrpcBadMethod", Message: "bad method", HTTPStatus: 405}
	ErrWebrpcBadRequest         = WebRPCError{Code: -4, Name: "WebrpcBadRequest", Message: "bad request", HTTPStatus: 400}
	ErrWebrpcBadResponse        = WebRPCError{Code: -5, Name: "WebrpcBadResponse", Message: "bad response", HTTPStatus: 500}
	ErrWebrpcServerPanic        = WebRPCError{Code: -6, Name: "WebrpcServerPanic", Message: "server panic", HTTPStatus: 500}
	ErrWebrpcInternalError      = WebRPCError{Code: -7, Name: "WebrpcInternalError", Message: "internal error", HTTPStatus: 500}
	ErrWebrpcClientDisconnected = WebRPCError{Code: -8, Name: "WebrpcClientDisconnected", Message: "client disconnected", HTTPStatus: 400}
	ErrWebrpcStreamLost         = WebRPCError{Code: -9, Name: "WebrpcStreamLost", Message: "stream lost", HTTPStatus: 400}
	ErrWebrpcStreamFinished     = WebRPCError{Code: -10, Name: "WebrpcStreamFinished", Message: "stream finished", HTTPStatus: 200}
)

// Schema errors
var (
	ErrUnauthorized      = WebRPCError{Code: 1000, Name: "Unauthorized", Message: "Unauthorized access", HTTPStatus: 401}
	ErrTenantNotFound    = WebRPCError{Code: 1001, Name: "TenantNotFound", Message: "Tenant not found", HTTPStatus: 404}
	ErrEmailAlreadyInUse = WebRPCError{Code: 2000, Name: "EmailAlreadyInUse", Message: "Could not create account as the email is already in use", HTTPStatus: 409}
)
