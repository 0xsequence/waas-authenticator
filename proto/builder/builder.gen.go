// sequence-builder v0.1.0 4a46de64365e2771e2a31710589017bfc488d6cd
// --
// Code generated by webrpc-gen@v0.19.3 with golang generator. DO NOT EDIT.
//
// webrpc-gen -schema=builder.ridl -target=golang -pkg=builder -client -server -out=./builder.gen.go
package builder

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
	return "4a46de64365e2771e2a31710589017bfc488d6cd"
}

//
// Common types
//

type EmailTemplateType uint8

const (
	EmailTemplateType_UNKNOWN EmailTemplateType = 0
	EmailTemplateType_LOGIN   EmailTemplateType = 1
	EmailTemplateType_GUARD   EmailTemplateType = 2
)

var EmailTemplateType_name = map[uint8]string{
	0: "UNKNOWN",
	1: "LOGIN",
	2: "GUARD",
}

var EmailTemplateType_value = map[string]uint8{
	"UNKNOWN": 0,
	"LOGIN":   1,
	"GUARD":   2,
}

func (x EmailTemplateType) String() string {
	return EmailTemplateType_name[uint8(x)]
}

func (x EmailTemplateType) MarshalText() ([]byte, error) {
	return []byte(EmailTemplateType_name[uint8(x)]), nil
}

func (x *EmailTemplateType) UnmarshalText(b []byte) error {
	*x = EmailTemplateType(EmailTemplateType_value[string(b)])
	return nil
}

func (x *EmailTemplateType) Is(values ...EmailTemplateType) bool {
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

// db table: 'email_templates'
type EmailTemplate struct {
	ID           uint64             `json:"id" db:"id,omitempty"`
	TemplateType *EmailTemplateType `json:"templateType" db:"template_type"`
	ProjectID    uint64             `json:"projectId" db:"project_id"`
	Subject      string             `json:"subject" db:"subject"`
	IntroText    string             `json:"introText" db:"intro_text"`
	LogoURL      string             `json:"logoUrl" db:"logo_url"`
	Template     *string            `json:"template" db:"template"`
	FromEmail    *string            `json:"fromEmail" db:"from_email"`
	Placeholders []string           `json:"placeholders" db:"placeholders"`
	SesConfig    *SESSettings       `json:"sesConfig" db:"ses_config"`
	CreatedAt    time.Time          `json:"createdAt" db:"created_at"`
	UpdatedAt    time.Time          `json:"updatedAt" db:"updated_at"`
	DeletedAt    *time.Time         `json:"deletedAt,omitempty" db:"deleted_at,omitempty"`
}

type SESSettings struct {
	AccessRoleARN string `json:"accessRoleARN"`
	SourceARN     string `json:"sourceARN"`
}

var WebRPCServices = map[string][]string{
	"Builder": {
		"GetEmailTemplate",
	},
}

//
// Server types
//

type Builder interface {
	// Project > Email Templates
	//
	GetEmailTemplate(ctx context.Context, projectId uint64, templateType *EmailTemplateType) (*EmailTemplate, error)
}

//
// Client types
//

type BuilderClient interface {
	// Project > Email Templates
	//
	GetEmailTemplate(ctx context.Context, projectId uint64, templateType *EmailTemplateType) (*EmailTemplate, error)
}

//
// Server
//

type WebRPCServer interface {
	http.Handler
}

type builderServer struct {
	Builder
	OnError func(r *http.Request, rpcErr *WebRPCError)
}

func NewBuilderServer(svc Builder) *builderServer {
	return &builderServer{
		Builder: svc,
	}
}

func (s *builderServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	ctx = context.WithValue(ctx, ServiceNameCtxKey, "Builder")

	var handler func(ctx context.Context, w http.ResponseWriter, r *http.Request)
	switch r.URL.Path {
	case "/rpc/Builder/GetEmailTemplate":
		handler = s.serveGetEmailTemplateJSON
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

func (s *builderServer) serveGetEmailTemplateJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ctx = context.WithValue(ctx, MethodNameCtxKey, "GetEmailTemplate")

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to read request data: %w", err)))
		return
	}
	defer r.Body.Close()

	reqPayload := struct {
		Arg0 uint64             `json:"projectId"`
		Arg1 *EmailTemplateType `json:"templateType"`
	}{}
	if err := json.Unmarshal(reqBody, &reqPayload); err != nil {
		s.sendErrorJSON(w, r, ErrWebrpcBadRequest.WithCause(fmt.Errorf("failed to unmarshal request data: %w", err)))
		return
	}

	// Call service method implementation.
	ret0, err := s.Builder.GetEmailTemplate(ctx, reqPayload.Arg0, reqPayload.Arg1)
	if err != nil {
		rpcErr, ok := err.(WebRPCError)
		if !ok {
			rpcErr = ErrWebrpcEndpoint.WithCause(err)
		}
		s.sendErrorJSON(w, r, rpcErr)
		return
	}

	respPayload := struct {
		Ret0 *EmailTemplate `json:"emailTemplate"`
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

func (s *builderServer) sendErrorJSON(w http.ResponseWriter, r *http.Request, rpcErr WebRPCError) {
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

const BuilderPathPrefix = "/rpc/Builder/"

type builderClient struct {
	client HTTPClient
	urls   [1]string
}

func NewBuilderClient(addr string, client HTTPClient) BuilderClient {
	prefix := urlBase(addr) + BuilderPathPrefix
	urls := [1]string{
		prefix + "GetEmailTemplate",
	}
	return &builderClient{
		client: client,
		urls:   urls,
	}
}

func (c *builderClient) GetEmailTemplate(ctx context.Context, projectId uint64, templateType *EmailTemplateType) (*EmailTemplate, error) {
	in := struct {
		Arg0 uint64             `json:"projectId"`
		Arg1 *EmailTemplateType `json:"templateType"`
	}{projectId, templateType}
	out := struct {
		Ret0 *EmailTemplate `json:"emailTemplate"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[0], in, &out)
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
	ErrUnauthorized        = WebRPCError{Code: 1000, Name: "Unauthorized", Message: "Unauthorized access", HTTPStatus: 401}
	ErrPermissionDenied    = WebRPCError{Code: 1001, Name: "PermissionDenied", Message: "Permission denied", HTTPStatus: 403}
	ErrSessionExpired      = WebRPCError{Code: 1002, Name: "SessionExpired", Message: "Session expired", HTTPStatus: 403}
	ErrMethodNotFound      = WebRPCError{Code: 1003, Name: "MethodNotFound", Message: "Method not found", HTTPStatus: 404}
	ErrRequestConflict     = WebRPCError{Code: 1004, Name: "RequestConflict", Message: "Conflict with target resource", HTTPStatus: 409}
	ErrTimeout             = WebRPCError{Code: 2000, Name: "Timeout", Message: "Request timed out", HTTPStatus: 408}
	ErrInvalidArgument     = WebRPCError{Code: 2001, Name: "InvalidArgument", Message: "Invalid argument", HTTPStatus: 400}
	ErrNotFound            = WebRPCError{Code: 3000, Name: "NotFound", Message: "Resource not found", HTTPStatus: 400}
	ErrUserNotFound        = WebRPCError{Code: 3001, Name: "UserNotFound", Message: "User not found", HTTPStatus: 400}
	ErrProjectNotFound     = WebRPCError{Code: 3002, Name: "ProjectNotFound", Message: "Project not found", HTTPStatus: 400}
	ErrInvalidTier         = WebRPCError{Code: 3003, Name: "InvalidTier", Message: "Invalid subscription tier", HTTPStatus: 400}
	ErrEmailTemplateExists = WebRPCError{Code: 3004, Name: "EmailTemplateExists", Message: "Email Template exists", HTTPStatus: 409}
	ErrSubscriptionLimit   = WebRPCError{Code: 3005, Name: "SubscriptionLimit", Message: "Subscription limit reached", HTTPStatus: 402}
	ErrFeatureNotIncluded  = WebRPCError{Code: 3006, Name: "FeatureNotIncluded", Message: "Feature not included", HTTPStatus: 402}
	ErrInvalidNetwork      = WebRPCError{Code: 3007, Name: "InvalidNetwork", Message: "Invalid network", HTTPStatus: 400}
	ErrInvitationExpired   = WebRPCError{Code: 4000, Name: "InvitationExpired", Message: "Invitation code is expired", HTTPStatus: 400}
	ErrAlreadyCollaborator = WebRPCError{Code: 4001, Name: "AlreadyCollaborator", Message: "Already a collaborator", HTTPStatus: 409}
)
