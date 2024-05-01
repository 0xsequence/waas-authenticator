// sequence-wallet v0.1.0 7eee63e03bddc9416b3da9ff75fd6eef2cc2baa0
// --
// Code generated by webrpc-gen@v0.18.6 with golang generator. DO NOT EDIT.
//
// webrpc-gen -schema=wallet.ridl -target=golang -pkg=api -client -out=./clients/wallet.gen.go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/0xsequence/go-sequence/lib/prototyp"
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
	return "7eee63e03bddc9416b3da9ff75fd6eef2cc2baa0"
}

//
// Common types
//

type Intent struct {
	Version    string       `json:"version"`
	Name       string       `json:"name"`
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
	Code string      `json:"code"`
	Data interface{} `json:"data"`
}

type SortOrder uint32

const (
	SortOrder_DESC SortOrder = 0
	SortOrder_ASC  SortOrder = 1
)

var SortOrder_name = map[uint32]string{
	0: "DESC",
	1: "ASC",
}

var SortOrder_value = map[string]uint32{
	"DESC": 0,
	"ASC":  1,
}

func (x SortOrder) String() string {
	return SortOrder_name[uint32(x)]
}

func (x SortOrder) MarshalText() ([]byte, error) {
	return []byte(SortOrder_name[uint32(x)]), nil
}

func (x *SortOrder) UnmarshalText(b []byte) error {
	*x = SortOrder(SortOrder_value[string(b)])
	return nil
}

func (x *SortOrder) Is(values ...SortOrder) bool {
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

// Project represents a project that can be used to configure the wallet as a service.
type Project struct {
	Id        uint64        `json:"id" db:"id,omitempty"`
	Name      string        `json:"name" db:"name"`
	JwtAlg    string        `json:"jwtAlg" db:"jwt_alg"`
	JwtSecret *string       `json:"jwtSecret" db:"jwt_secret"`
	JwtPublic *string       `json:"jwtPublic" db:"jwt_public"`
	UserSalt  prototyp.Hash `json:"user_salt" db:"user_salt"`
	Salt      prototyp.Hash `json:"-" db:"salt"`
	UpdatedAt *time.Time    `json:"updatedAt,omitempty" db:"updated_at,omitempty"`
	CreatedAt *time.Time    `json:"createdAt,omitempty" db:"created_at,omitempty"`
}

// ProjectWallet is an wallet that can be used by a project. The wallet
// can be used to sign transactions and messages.
type ProjectWallet struct {
	Id            uint64        `json:"id" db:"id,omitempty"`
	ProjectID     uint64        `json:"projectID" db:"project_id"`
	WalletIndex   uint64        `json:"walletIndex" db:"wallet_index"`
	WalletAddress prototyp.Hash `json:"walletAddress" db:"wallet_address"`
	UserID        string        `json:"userId" db:"user_id"`
	UpdatedAt     *time.Time    `json:"updatedAt,omitempty" db:"updated_at,omitempty"`
	CreatedAt     *time.Time    `json:"createdAt,omitempty" db:"created_at,omitempty"`
}

// ProjectWalletConfig is a configuration for a project wallet. The configuration
// can be used to configure the wallet for a project.
type ProjectWalletConfig struct {
	Id        uint64        `json:"id" db:"id,omitempty"`
	ProjectID uint64        `json:"projectID" db:"project_id"`
	Address   prototyp.Hash `json:"address" db:"address"`
	Config    string        `json:"config" db:"config"`
	UpdatedAt *time.Time    `json:"updatedAt,omitempty" db:"updated_at,omitempty"`
	CreatedAt *time.Time    `json:"createdAt,omitempty" db:"created_at,omitempty"`
}

type Transaction struct {
	To            string `json:"to"`
	Value         string `json:"value"`
	GasLimit      string `json:"gasLimit"`
	Data          string `json:"data"`
	DelegateCall  bool   `json:"delegateCall"`
	RevertOnError bool   `json:"revertOnError"`
}

type TransactionBundle struct {
	ChainID      string         `json:"chainID"`
	Nonce        string         `json:"nonce"`
	Transactions []*Transaction `json:"transactions"`
}

type SignMessage struct {
	ChainID string `json:"chainID"`
	Message string `json:"message"`
}

type ParentWalletStatus struct {
	ChainID  string `json:"chainID"`
	Address  string `json:"address"`
	Deployed bool   `json:"deployed"`
}

// Chain represents a blockchain network.
type Chain struct {
	Id   uint64 `json:"id"`
	Name string `json:"name"`
}

// Page represents a results page. This can be used both to request a page and
// to store the state of a page.
type Page struct {
	// Common for both numbered pages and cursor: Number of items per page
	// TODO: REMOVE..
	PageSize *uint32 `json:"pageSize"`
	// Numbered pages: Page number, this is multiplied by the value of the <pageSize> parameter.
	// TODO: REMOVE..
	Page *uint32 `json:"page"`
	// Number of total items on this query.
	// TODO: REMOVE..
	TotalRecords *uint64 `json:"totalRecords"`
	// Cursor: column to compare before/after to
	Column *string `json:"column"`
	// Cursor: return column < before - include to get previous page
	Before *interface{} `json:"before"`
	// Cursor: return column > after - include to get next page
	After *interface{} `json:"after"`
	// Sorting filter
	Sort []*SortBy `json:"sort"`
}

type SortBy struct {
	Column string    `json:"column"`
	Order  SortOrder `json:"order"`
}

type ProvidedSignature struct {
	Signature string `json:"Signature"`
	Digest    string `json:"Digest"`
	Address   string `json:"Address"`
}

type ProjectWalletPreConfig struct {
	ProjectRecoveryAddress string                      `json:"projectRecoveryAddress"`
	UserMapRules           *ProjectSessionUserMapRules `json:"userMapRules"`
}

type ProjectSessionUserMapRules struct {
	AllowIdTokens                     bool   `json:"allowIdTokens" db:"allow_id_tokens"`
	AllowEmails                       bool   `json:"allowEmails" db:"allow_emails"`
	AllowPhones                       bool   `json:"allowPhones" db:"allow_phones"`
	UserIdTemplate                    string `json:"userIdTemplate" db:"user_id_template"`
	IdTokenTrustedAuthenticatorIssuer string `json:"idTokenTrustedAuthenticatorIssuer" db:"id_token_trusted_authenticator_issuer"`
}

type SessionAuthProof struct {
	Wallet     string               `json:"wallet"`
	Message    *SignMessage         `json:"message"`
	Signatures []*ProvidedSignature `json:"signatures"`
}

type MiniSequenceContext struct {
	Factory    string `json:"factory"`
	MainModule string `json:"mainModule"`
}

var WebRPCServices = map[string][]string{
	"WaaS": {
		"CreateProject",
		"DeployProjectParentWallet",
		"ProjectParentConfig",
		"ProjectParentWallet",
		"ProjectParentWalletStatus",
		"ProjectWallets",
		"ProjectUserSalt",
		"GetProjectParentWalletDeployCalldata",
		"ProjectWallet",
		"SequenceContext",
		"UserSalt",
		"UseHotWallet",
		"Wallets",
		"GenTransaction",
		"SendTransaction",
		"SignMessage",
		"GetSession",
		"RegisterSession",
		"StartSessionValidation",
		"FinishValidateSession",
		"InvalidateSession",
		"SessionAuthProof",
		"FederateAccount",
		"RemoveAccount",
		"SendIntent",
		"ChainList",
	},
}

//
// Server types
//

type WaaS interface {
	//
	// system-admin methods
	//
	CreateProject(ctx context.Context, projectID uint64, name string, config *ProjectWalletPreConfig, jwtAlg string, jwtSecret *string, jwtPublic *string) (*Project, error)
	DeployProjectParentWallet(ctx context.Context, projectID uint64, chainID string) (string, string, error)
	ProjectParentConfig(ctx context.Context, projectID uint64) (string, error)
	ProjectParentWallet(ctx context.Context, projectID uint64) (string, error)
	ProjectParentWalletStatus(ctx context.Context, projectID uint64) ([]*ParentWalletStatus, error)
	ProjectWallets(ctx context.Context, projectID uint64, page *Page) ([]*ProjectWallet, *Page, error)
	// NOTICE: This is NOT the salt used for the guard
	// this salt is used to deterministically being able to compute the relationship
	// userId <-> wallet, that way the API can't map users to the wrong wallet
	ProjectUserSalt(ctx context.Context, projectID uint64) (string, error)
	// similar method to DeployProjectParentWallet, but allows anyone to call it to get
	// the transaction calldata to do a parent wallet deployment manually.
	GetProjectParentWalletDeployCalldata(ctx context.Context, projectID uint64, chainID string) (string, string, string, error)
	// these methods are used by the dss during setup, they reduce the
	// amount of configuration that needs to be manually passed around
	ProjectWallet(ctx context.Context) (string, error)
	SequenceContext(ctx context.Context) (*MiniSequenceContext, error)
	UserSalt(ctx context.Context) (string, error)
	UseHotWallet(ctx context.Context, walletAddress string) (bool, error)
	// wallet rpc caller
	Wallets(ctx context.Context, page *Page) ([]*ProjectWallet, *Page, error)
	// wallet rpc using sdk
	GenTransaction(ctx context.Context, intent *Intent) (*TransactionBundle, error)
	SendTransaction(ctx context.Context, intent *Intent, result *TransactionBundle, signatures []*ProvidedSignature) (*IntentResponse, error)
	SignMessage(ctx context.Context, intent *Intent, message *SignMessage, signatures []*ProvidedSignature) (*IntentResponse, error)
	GetSession(ctx context.Context, sessionId string) (*IntentResponse, error)
	RegisterSession(ctx context.Context, userID string, intent *Intent) (*IntentResponse, error)
	StartSessionValidation(ctx context.Context, walletAddress string, sessionId string, deviceMetadata string) (*IntentResponse, error)
	FinishValidateSession(ctx context.Context, sessionId string, salt string, challenge string) (*IntentResponse, error)
	InvalidateSession(ctx context.Context, sessionId string) (bool, error)
	SessionAuthProof(ctx context.Context, intent *Intent, proof *SessionAuthProof) (*IntentResponse, error)
	FederateAccount(ctx context.Context, userID string, intent *Intent) (*IntentResponse, error)
	RemoveAccount(ctx context.Context, intent *Intent) (*IntentResponse, error)
	// Generic send intent method
	SendIntent(ctx context.Context, intent *Intent) (*IntentResponse, error)
	// utilities
	ChainList(ctx context.Context) ([]*Chain, error)
}

//
// Client types
//

type WaaSClient interface {
	//
	// system-admin methods
	//
	CreateProject(ctx context.Context, projectID uint64, name string, config *ProjectWalletPreConfig, jwtAlg string, jwtSecret *string, jwtPublic *string) (*Project, error)
	DeployProjectParentWallet(ctx context.Context, projectID uint64, chainID string) (string, string, error)
	ProjectParentConfig(ctx context.Context, projectID uint64) (string, error)
	ProjectParentWallet(ctx context.Context, projectID uint64) (string, error)
	ProjectParentWalletStatus(ctx context.Context, projectID uint64) ([]*ParentWalletStatus, error)
	ProjectWallets(ctx context.Context, projectID uint64, page *Page) ([]*ProjectWallet, *Page, error)
	// NOTICE: This is NOT the salt used for the guard
	// this salt is used to deterministically being able to compute the relationship
	// userId <-> wallet, that way the API can't map users to the wrong wallet
	ProjectUserSalt(ctx context.Context, projectID uint64) (string, error)
	// similar method to DeployProjectParentWallet, but allows anyone to call it to get
	// the transaction calldata to do a parent wallet deployment manually.
	GetProjectParentWalletDeployCalldata(ctx context.Context, projectID uint64, chainID string) (string, string, string, error)
	// these methods are used by the dss during setup, they reduce the
	// amount of configuration that needs to be manually passed around
	ProjectWallet(ctx context.Context) (string, error)
	SequenceContext(ctx context.Context) (*MiniSequenceContext, error)
	UserSalt(ctx context.Context) (string, error)
	UseHotWallet(ctx context.Context, walletAddress string) (bool, error)
	// wallet rpc caller
	Wallets(ctx context.Context, page *Page) ([]*ProjectWallet, *Page, error)
	// wallet rpc using sdk
	GenTransaction(ctx context.Context, intent *Intent) (*TransactionBundle, error)
	SendTransaction(ctx context.Context, intent *Intent, result *TransactionBundle, signatures []*ProvidedSignature) (*IntentResponse, error)
	SignMessage(ctx context.Context, intent *Intent, message *SignMessage, signatures []*ProvidedSignature) (*IntentResponse, error)
	GetSession(ctx context.Context, sessionId string) (*IntentResponse, error)
	RegisterSession(ctx context.Context, userID string, intent *Intent) (*IntentResponse, error)
	StartSessionValidation(ctx context.Context, walletAddress string, sessionId string, deviceMetadata string) (*IntentResponse, error)
	FinishValidateSession(ctx context.Context, sessionId string, salt string, challenge string) (*IntentResponse, error)
	InvalidateSession(ctx context.Context, sessionId string) (bool, error)
	SessionAuthProof(ctx context.Context, intent *Intent, proof *SessionAuthProof) (*IntentResponse, error)
	FederateAccount(ctx context.Context, userID string, intent *Intent) (*IntentResponse, error)
	RemoveAccount(ctx context.Context, intent *Intent) (*IntentResponse, error)
	// Generic send intent method
	SendIntent(ctx context.Context, intent *Intent) (*IntentResponse, error)
	// utilities
	ChainList(ctx context.Context) ([]*Chain, error)
}

//
// Client
//

const WaaSPathPrefix = "/rpc/WaaS/"

type waaSClient struct {
	client HTTPClient
	urls   [26]string
}

func NewWaaSClient(addr string, client HTTPClient) WaaSClient {
	prefix := urlBase(addr) + WaaSPathPrefix
	urls := [26]string{
		prefix + "CreateProject",
		prefix + "DeployProjectParentWallet",
		prefix + "ProjectParentConfig",
		prefix + "ProjectParentWallet",
		prefix + "ProjectParentWalletStatus",
		prefix + "ProjectWallets",
		prefix + "ProjectUserSalt",
		prefix + "GetProjectParentWalletDeployCalldata",
		prefix + "ProjectWallet",
		prefix + "SequenceContext",
		prefix + "UserSalt",
		prefix + "UseHotWallet",
		prefix + "Wallets",
		prefix + "GenTransaction",
		prefix + "SendTransaction",
		prefix + "SignMessage",
		prefix + "GetSession",
		prefix + "RegisterSession",
		prefix + "StartSessionValidation",
		prefix + "FinishValidateSession",
		prefix + "InvalidateSession",
		prefix + "SessionAuthProof",
		prefix + "FederateAccount",
		prefix + "RemoveAccount",
		prefix + "SendIntent",
		prefix + "ChainList",
	}
	return &waaSClient{
		client: client,
		urls:   urls,
	}
}

func (c *waaSClient) CreateProject(ctx context.Context, projectID uint64, name string, config *ProjectWalletPreConfig, jwtAlg string, jwtSecret *string, jwtPublic *string) (*Project, error) {
	in := struct {
		Arg0 uint64                  `json:"projectID"`
		Arg1 string                  `json:"name"`
		Arg2 *ProjectWalletPreConfig `json:"config"`
		Arg3 string                  `json:"jwtAlg"`
		Arg4 *string                 `json:"jwtSecret"`
		Arg5 *string                 `json:"jwtPublic"`
	}{projectID, name, config, jwtAlg, jwtSecret, jwtPublic}
	out := struct {
		Ret0 *Project `json:"project"`
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

func (c *waaSClient) DeployProjectParentWallet(ctx context.Context, projectID uint64, chainID string) (string, string, error) {
	in := struct {
		Arg0 uint64 `json:"projectID"`
		Arg1 string `json:"chainID"`
	}{projectID, chainID}
	out := struct {
		Ret0 string `json:"address"`
		Ret1 string `json:"txnHash"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[1], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, out.Ret1, err
}

func (c *waaSClient) ProjectParentConfig(ctx context.Context, projectID uint64) (string, error) {
	in := struct {
		Arg0 uint64 `json:"projectID"`
	}{projectID}
	out := struct {
		Ret0 string `json:"config"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[2], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) ProjectParentWallet(ctx context.Context, projectID uint64) (string, error) {
	in := struct {
		Arg0 uint64 `json:"projectID"`
	}{projectID}
	out := struct {
		Ret0 string `json:"address"`
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

func (c *waaSClient) ProjectParentWalletStatus(ctx context.Context, projectID uint64) ([]*ParentWalletStatus, error) {
	in := struct {
		Arg0 uint64 `json:"projectID"`
	}{projectID}
	out := struct {
		Ret0 []*ParentWalletStatus `json:"parentWalletStatus"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[4], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) ProjectWallets(ctx context.Context, projectID uint64, page *Page) ([]*ProjectWallet, *Page, error) {
	in := struct {
		Arg0 uint64 `json:"projectID"`
		Arg1 *Page  `json:"page"`
	}{projectID, page}
	out := struct {
		Ret0 []*ProjectWallet `json:"wallets"`
		Ret1 *Page            `json:"page"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[5], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, out.Ret1, err
}

func (c *waaSClient) ProjectUserSalt(ctx context.Context, projectID uint64) (string, error) {
	in := struct {
		Arg0 uint64 `json:"projectID"`
	}{projectID}
	out := struct {
		Ret0 string `json:"salt"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[6], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) GetProjectParentWalletDeployCalldata(ctx context.Context, projectID uint64, chainID string) (string, string, string, error) {
	in := struct {
		Arg0 uint64 `json:"projectID"`
		Arg1 string `json:"chainID"`
	}{projectID, chainID}
	out := struct {
		Ret0 string `json:"parentWalletAddress"`
		Ret1 string `json:"toAddress"`
		Ret2 string `json:"calldata"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[7], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, out.Ret1, out.Ret2, err
}

func (c *waaSClient) ProjectWallet(ctx context.Context) (string, error) {
	out := struct {
		Ret0 string `json:"address"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[8], nil, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) SequenceContext(ctx context.Context) (*MiniSequenceContext, error) {
	out := struct {
		Ret0 *MiniSequenceContext `json:"context"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[9], nil, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) UserSalt(ctx context.Context) (string, error) {
	out := struct {
		Ret0 string `json:"salt"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[10], nil, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) UseHotWallet(ctx context.Context, walletAddress string) (bool, error) {
	in := struct {
		Arg0 string `json:"walletAddress"`
	}{walletAddress}
	out := struct {
		Ret0 bool `json:"status"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[11], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) Wallets(ctx context.Context, page *Page) ([]*ProjectWallet, *Page, error) {
	in := struct {
		Arg0 *Page `json:"page"`
	}{page}
	out := struct {
		Ret0 []*ProjectWallet `json:"wallets"`
		Ret1 *Page            `json:"page"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[12], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, out.Ret1, err
}

func (c *waaSClient) GenTransaction(ctx context.Context, intent *Intent) (*TransactionBundle, error) {
	in := struct {
		Arg0 *Intent `json:"intent"`
	}{intent}
	out := struct {
		Ret0 *TransactionBundle `json:"result"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[13], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) SendTransaction(ctx context.Context, intent *Intent, result *TransactionBundle, signatures []*ProvidedSignature) (*IntentResponse, error) {
	in := struct {
		Arg0 *Intent              `json:"intent"`
		Arg1 *TransactionBundle   `json:"result"`
		Arg2 []*ProvidedSignature `json:"signatures"`
	}{intent, result, signatures}
	out := struct {
		Ret0 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[14], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) SignMessage(ctx context.Context, intent *Intent, message *SignMessage, signatures []*ProvidedSignature) (*IntentResponse, error) {
	in := struct {
		Arg0 *Intent              `json:"intent"`
		Arg1 *SignMessage         `json:"message"`
		Arg2 []*ProvidedSignature `json:"signatures"`
	}{intent, message, signatures}
	out := struct {
		Ret0 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[15], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) GetSession(ctx context.Context, sessionId string) (*IntentResponse, error) {
	in := struct {
		Arg0 string `json:"sessionId"`
	}{sessionId}
	out := struct {
		Ret0 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[16], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) RegisterSession(ctx context.Context, userID string, intent *Intent) (*IntentResponse, error) {
	in := struct {
		Arg0 string  `json:"userID"`
		Arg1 *Intent `json:"intent"`
	}{userID, intent}
	out := struct {
		Ret0 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[17], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) StartSessionValidation(ctx context.Context, walletAddress string, sessionId string, deviceMetadata string) (*IntentResponse, error) {
	in := struct {
		Arg0 string `json:"walletAddress"`
		Arg1 string `json:"sessionId"`
		Arg2 string `json:"deviceMetadata"`
	}{walletAddress, sessionId, deviceMetadata}
	out := struct {
		Ret0 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[18], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) FinishValidateSession(ctx context.Context, sessionId string, salt string, challenge string) (*IntentResponse, error) {
	in := struct {
		Arg0 string `json:"sessionId"`
		Arg1 string `json:"salt"`
		Arg2 string `json:"challenge"`
	}{sessionId, salt, challenge}
	out := struct {
		Ret0 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[19], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) InvalidateSession(ctx context.Context, sessionId string) (bool, error) {
	in := struct {
		Arg0 string `json:"sessionId"`
	}{sessionId}
	out := struct {
		Ret0 bool `json:"status"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[20], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) SessionAuthProof(ctx context.Context, intent *Intent, proof *SessionAuthProof) (*IntentResponse, error) {
	in := struct {
		Arg0 *Intent           `json:"intent"`
		Arg1 *SessionAuthProof `json:"proof"`
	}{intent, proof}
	out := struct {
		Ret0 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[21], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) FederateAccount(ctx context.Context, userID string, intent *Intent) (*IntentResponse, error) {
	in := struct {
		Arg0 string  `json:"userID"`
		Arg1 *Intent `json:"intent"`
	}{userID, intent}
	out := struct {
		Ret0 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[22], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) RemoveAccount(ctx context.Context, intent *Intent) (*IntentResponse, error) {
	in := struct {
		Arg0 *Intent `json:"intent"`
	}{intent}
	out := struct {
		Ret0 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[23], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) SendIntent(ctx context.Context, intent *Intent) (*IntentResponse, error) {
	in := struct {
		Arg0 *Intent `json:"intent"`
	}{intent}
	out := struct {
		Ret0 *IntentResponse `json:"response"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[24], in, &out)
	if resp != nil {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = ErrWebrpcRequestFailed.WithCause(fmt.Errorf("failed to close response body: %w", cerr))
		}
	}

	return out.Ret0, err
}

func (c *waaSClient) ChainList(ctx context.Context) ([]*Chain, error) {
	out := struct {
		Ret0 []*Chain `json:"chains"`
	}{}

	resp, err := doHTTPRequest(ctx, c.client, c.urls[25], nil, &out)
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
	HTTPRequestCtxKey              = &contextKey{"HTTPRequest"}

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
	ErrAborted  = WebRPCError{Code: 1005, Name: "Aborted", Message: "Request aborted", HTTPStatus: 400}
	ErrNotFound = WebRPCError{Code: 3000, Name: "NotFound", Message: "Resource not found", HTTPStatus: 400}
)
