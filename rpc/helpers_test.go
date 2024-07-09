package rpc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/0xsequence/waas-authenticator/rpc"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/goware/validation"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/localstack"
	"github.com/testcontainers/testcontainers-go/wait"
)

var awsEndpoint string

func TestMain(m *testing.M) {
	ep, terminate := initLocalstack()
	defer terminate()
	awsEndpoint = ep
	code := m.Run()
	os.Exit(code)
}

func initRPC(t *testing.T, options ...func(*config.Config)) *rpc.RPC {
	cfg := initConfig(t, awsEndpoint)
	for _, opt := range options {
		opt(cfg)
	}

	svc, err := rpc.New(cfg, &http.Client{Transport: &testTransport{RoundTripper: http.DefaultTransport}})
	if err != nil {
		t.Fatal(err)
	}
	svc.Wallets = newWalletServiceMock(nil)
	return svc
}

func initRPCWithClient(t *testing.T, client *http.Client, options ...func(*config.Config)) *rpc.RPC {
	cfg := initConfig(t, awsEndpoint)
	for _, opt := range options {
		opt(cfg)
	}

	svc, err := rpc.New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	svc.Wallets = newWalletServiceMock(nil)
	return svc
}

func generateSignedIntent(t *testing.T, name intents.IntentName, data any, session intents.Session) *proto.Intent {
	intent := &intents.Intent{
		Version:    "1.0.0",
		Name:       name,
		ExpiresAt:  uint64(time.Now().Add(1 * time.Minute).Unix()),
		IssuedAt:   uint64(time.Now().Unix()),
		Data:       data,
		Signatures: nil,
	}
	require.NoError(t, session.Sign(intent))
	signatures := make([]*proto.Signature, len(intent.Signatures))
	for i, s := range intent.Signatures {
		signatures[i] = &proto.Signature{
			SessionID: s.SessionID,
			Signature: s.Signature,
		}
	}
	return &proto.Intent{
		Version:    intent.Version,
		Name:       proto.IntentName(intent.Name),
		ExpiresAt:  intent.ExpiresAt,
		IssuedAt:   intent.IssuedAt,
		Data:       intent.Data,
		Signatures: signatures,
	}
}

func initConfig(t *testing.T, awsEndpoint string) *config.Config {
	return &config.Config{
		Region: "us-east-1",
		Admin: config.AdminConfig{
			PublicKey: `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz+WUoYyHdSNN802C9q3Z
fn9U1/hGblhsaKmnDMW1TrNcIbjp+W1iAXBgaGlyKpPq6pO6AezWswBTBJfRlXaJ
Uqw6XfQxkv1JTJqoRRI3dRs7EopYr53eEM0xWx3q1EDCYr//z2XCG69XiIr3jD/4
ndaCARls5nSx7ffc94dnxZGnUMIlY/hoftNoaLu1G6yVLJmBxhIv4HkpqdOa0QON
P+cfxrocQl7dkdn31TKdrAfaZa0P7VIPiqE9dxN3vuhMFJoMWmWFlvpV8LXzLlm3
O/1N3VmFauveH6CaYZ1uiBvwsNUiKczJWlPloDRNO/HKsH1gF/EqfF9ObU1WGP3A
QwIDAQAB
-----END RSA PUBLIC KEY-----`,
		},
		Database: config.DatabaseConfig{
			TenantsTable:              "TenantsTable",
			AccountsTable:             "AccountsTable",
			SessionsTable:             "SessionsTable",
			VerificationContextsTable: "VerificationContextsTable",
		},
		KMS: config.KMSConfig{
			SigningKey:         "arn:aws:kms:us-east-1:000000000000:key/5edb0219-8da9-4842-98fb-e83c6316f3bd",
			TenantKeys:         []string{"arn:aws:kms:us-east-1:000000000000:key/27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79"},
			DefaultSessionKeys: []string{"arn:aws:kms:us-east-1:000000000000:key/27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79"},
		},
		Endpoints: config.EndpointsConfig{
			AWSEndpoint: awsEndpoint,
		},
		Builder: config.BuilderConfig{
			SecretID: "BuilderJWT",
		},
		SES: config.SESConfig{
			Source: "noreply@local.auth.sequence.app",
		},
	}
}

func issueAccessTokenAndRunJwksServer(t *testing.T, optTokenBuilderFn ...func(*jwt.Builder, string)) (iss string, tok string, close func()) {
	jwtKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwtKey, err := jwk.FromRaw(jwtKeyRaw)
	require.NoError(t, err)
	require.NoError(t, jwtKey.Set(jwk.KeyIDKey, "key-id"))
	jwtPubKey, err := jwtKey.PublicKey()
	require.NoError(t, err)
	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(jwtPubKey))

	var uri string
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			openidConfig := map[string]any{"jwks_uri": uri}
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(openidConfig))
			return
		}

		m, err := jwtPubKey.AsMap(r.Context())
		m["alg"] = "RS256"
		require.NoError(t, err)
		pkd := map[string]any{"keys": []any{m}}

		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		require.NoError(t, json.NewEncoder(w).Encode(pkd))
	}))
	uri = jwksServer.URL

	tokBuilder := jwt.NewBuilder().
		Issuer(jwksServer.URL).
		Audience([]string{"audience"}).
		Subject("subject")

	if len(optTokenBuilderFn) > 0 && optTokenBuilderFn[0] != nil {
		optTokenBuilderFn[0](tokBuilder, jwksServer.URL)
	}

	tokRaw, err := tokBuilder.Build()
	require.NoError(t, err)
	tokBytes, err := jwt.Sign(tokRaw, jwt.WithKey(jwa.RS256, jwtKey))
	require.NoError(t, err)

	return jwksServer.URL, string(tokBytes), jwksServer.Close
}

func initLocalstack() (string, func()) {
	ctx := context.Background()
	lc, err := localstack.RunContainer(context.Background(),
		testcontainers.WithImage("localstack/localstack:3.4"),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				WaitingFor: wait.ForAll(
					wait.ForHTTP("/_localstack/health").WithPort("4566/tcp"),
					wait.ForLog("Finished bootstrapping localstack resources!"),
				).WithDeadline(60 * time.Second),
				Files: []testcontainers.ContainerFile{
					{
						HostFilePath:      "../docker/awslocal_ready_hook.sh",
						ContainerFilePath: "/etc/localstack/init/ready.d/awslocal_ready_hook.sh",
						FileMode:          0777,
					},
				},
			},
		}),
	)
	if err != nil {
		panic(err)
	}
	terminate := func() {
		lc.Terminate(context.Background())
	}

	mappedPort, err := lc.MappedPort(ctx, "4566/tcp")
	if err != nil {
		terminate()
		panic(err)
	}

	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		terminate()
		panic(err)
	}
	defer provider.Close()

	host, err := provider.DaemonHost(ctx)
	if err != nil {
		terminate()
		panic(err)
	}

	endpoint := fmt.Sprintf("http://%s:%d", host, mappedPort.Int())
	return endpoint, terminate
}

var currentProjectID atomic.Uint64

func newTenant(t *testing.T, enc *enclave.Enclave, issuer string) (*data.Tenant, *proto.TenantData) {
	att, err := enc.GetAttestation(context.Background(), nil)
	require.NoError(t, err)

	wallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)

	projectID := currentProjectID.Add(1)

	userSalt, _ := hexutil.Decode("0xa176de7902ef0781d2c6120cc5fd5add3048e1543f597ef4feae38391d234839")
	payload := &proto.TenantData{
		ProjectID:     projectID,
		PrivateKey:    wallet.PrivateKeyHex()[2:],
		ParentAddress: common.HexToAddress("0xcF104bc904E4dC1cCe0027aB9F9C905Ad3aE6c21"),
		UserSalt:      userSalt,
		SequenceContext: &proto.MiniSequenceContext{
			Factory:    "0xFaA5c0b14d1bED5C888Ca655B9a8A5911F78eF4A",
			MainModule: "0xfBf8f1A5E00034762D928f46d438B947f5d4065d",
		},
		UpgradeCode:     "CHANGEME",
		WaasAccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXJ0bmVyX2lkIjozfQ.g2fWwLrKPhTUpLFc7ZM9pMm4kEHGu8haCMzMOOGiqSM",
		OIDCProviders: []*proto.OpenIdProvider{
			{Issuer: issuer, Audience: []string{"audience"}},
			{Issuer: "https://" + strings.TrimPrefix(issuer, "http://"), Audience: []string{"audience"}},
		},
		AllowedOrigins: validation.Origins{"http://localhost"},
		KMSKeys:        []string{"arn:aws:kms:us-east-1:000000000000:key/27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79"},
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(context.Background(), att, "27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79", payload)
	require.NoError(t, err)

	return &data.Tenant{
		ProjectID:    projectID,
		Version:      1,
		EncryptedKey: encryptedKey,
		Algorithm:    algorithm,
		Ciphertext:   ciphertext,
		CreatedAt:    time.Now(),
	}, payload
}

func newTenantWithAuthConfig(t *testing.T, enc *enclave.Enclave, authCfg proto.AuthConfig) (*data.Tenant, *proto.TenantData) {
	att, err := enc.GetAttestation(context.Background(), nil)
	require.NoError(t, err)

	wallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)

	projectID := currentProjectID.Add(1)

	userSalt, _ := hexutil.Decode("0xa176de7902ef0781d2c6120cc5fd5add3048e1543f597ef4feae38391d234839")
	payload := &proto.TenantData{
		ProjectID:     projectID,
		PrivateKey:    wallet.PrivateKeyHex()[2:],
		ParentAddress: common.HexToAddress("0xcF104bc904E4dC1cCe0027aB9F9C905Ad3aE6c21"),
		UserSalt:      userSalt,
		SequenceContext: &proto.MiniSequenceContext{
			Factory:    "0xFaA5c0b14d1bED5C888Ca655B9a8A5911F78eF4A",
			MainModule: "0xfBf8f1A5E00034762D928f46d438B947f5d4065d",
		},
		UpgradeCode:     "CHANGEME",
		WaasAccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXJ0bmVyX2lkIjozfQ.g2fWwLrKPhTUpLFc7ZM9pMm4kEHGu8haCMzMOOGiqSM",
		AllowedOrigins:  validation.Origins{"http://localhost"},
		AuthConfig:      authCfg,
		KMSKeys:         []string{"arn:aws:kms:us-east-1:000000000000:key/27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79"},
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(context.Background(), att, "27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79", payload)
	require.NoError(t, err)

	return &data.Tenant{
		ProjectID:    projectID,
		Version:      1,
		EncryptedKey: encryptedKey,
		Algorithm:    algorithm,
		Ciphertext:   ciphertext,
		CreatedAt:    time.Now(),
	}, payload
}

func newAccount(t *testing.T, tnt *data.Tenant, enc *enclave.Enclave, identity proto.Identity, wallet *ethwallet.Wallet) *data.Account {
	att, err := enc.GetAttestation(context.Background(), nil)
	require.NoError(t, err)

	if wallet == nil {
		wallet, err = ethwallet.NewWalletFromRandomEntropy()
		require.NoError(t, err)
	}
	signingSession := intents.NewSessionP256K1(wallet)

	payload := &proto.AccountData{
		ProjectID: tnt.ProjectID,
		UserID:    fmt.Sprintf("%d|%s", tnt.ProjectID, signingSession.SessionID()),
		Identity:  identity.String(),
		CreatedAt: time.Now(),
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(context.Background(), att, "27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79", payload)
	require.NoError(t, err)

	return &data.Account{
		ProjectID:          tnt.ProjectID,
		Identity:           data.Identity(identity),
		UserID:             payload.UserID,
		Email:              "user@example.com",
		ProjectScopedEmail: fmt.Sprintf("%d|user@example.com", tnt.ProjectID),
		EncryptedKey:       encryptedKey,
		Algorithm:          algorithm,
		Ciphertext:         ciphertext,
		CreatedAt:          payload.CreatedAt,
	}
}

func newOIDCIdentity(issuer string) proto.Identity {
	return proto.Identity{
		Type:    proto.IdentityType_OIDC,
		Issuer:  issuer,
		Subject: "SUBJECT",
	}
}

func newEmailIdentity(email string) proto.Identity {
	return proto.Identity{
		Type:    proto.IdentityType_Email,
		Subject: email,
		Email:   email,
	}
}

func newSessionFromData(t *testing.T, tnt *data.Tenant, enc *enclave.Enclave, payload *proto.SessionData) *data.Session {
	att, err := enc.GetAttestation(context.Background(), nil)
	require.NoError(t, err)

	var identity proto.Identity
	require.NoError(t, identity.FromString(payload.Identity))

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(context.Background(), att, "27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79", payload)
	require.NoError(t, err)

	return &data.Session{
		ID:           payload.ID,
		ProjectID:    tnt.ProjectID,
		UserID:       payload.UserID,
		Identity:     payload.Identity,
		FriendlyName: "FriendlyName",
		EncryptedKey: encryptedKey,
		Algorithm:    algorithm,
		Ciphertext:   ciphertext,
		RefreshedAt:  time.Now(),
		CreatedAt:    time.Now(),
	}
}

func newSession(t *testing.T, tnt *data.Tenant, enc *enclave.Enclave, issuer string, signingSession intents.Session) *data.Session {
	if signingSession == nil {
		var err error
		wallet, err := ethwallet.NewWalletFromRandomEntropy()
		require.NoError(t, err)
		signingSession = intents.NewSessionP256K1(wallet)
	}

	identity := proto.Identity{
		Type:    proto.IdentityType_OIDC,
		Issuer:  issuer,
		Subject: "SUBJECT",
	}
	payload := &proto.SessionData{
		ID:        signingSession.SessionID(),
		ProjectID: tnt.ProjectID,
		UserID:    fmt.Sprintf("%d|%s", tnt.ProjectID, signingSession.SessionID()),
		Identity:  identity.String(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	return newSessionFromData(t, tnt, enc, payload)
}

func unmarshalResponse[T any](t *testing.T, data any) *T {
	b, err := json.Marshal(data)
	require.NoError(t, err)

	var res T
	require.NoError(t, json.Unmarshal(b, &res))
	return &res
}

type walletServiceMock struct {
	registeredUsers    map[string]struct{}
	registeredSessions map[string]struct{}
}

func (w walletServiceMock) InitiateAuth(ctx context.Context, intent *proto_wallet.Intent, answer string, challenge string) (*proto_wallet.IntentResponse, error) {
	return nil, nil
}

func (w walletServiceMock) InitiateEmailAuth(ctx context.Context, intent *proto_wallet.Intent, answerHash string, salt string) (*proto_wallet.IntentResponse, error) {
	return nil, nil
}

func (w walletServiceMock) UpdateProjectUserMapRules(ctx context.Context, projectID uint64, userMapRules *proto_wallet.ProjectSessionUserMapRules) error {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) GetProjectParentWalletDeployCalldata(ctx context.Context, projectID uint64, chainID string) (string, string, string, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) FederateAccount(ctx context.Context, userID string, intent *proto_wallet.Intent) (*proto_wallet.IntentResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) RemoveAccount(ctx context.Context, intent *proto_wallet.Intent) (*proto_wallet.IntentResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) ProjectParentWalletStatus(ctx context.Context, projectID uint64) ([]*proto_wallet.ParentWalletStatus, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) SessionAuthProof(ctx context.Context, intent *proto_wallet.Intent, proof *proto_wallet.SessionAuthProof) (*proto_wallet.IntentResponse, error) {
	//TODO implement me
	panic("implement me")
}

func newWalletServiceMock(registeredSessions []string) *walletServiceMock {
	m := &walletServiceMock{
		registeredSessions: make(map[string]struct{}),
		registeredUsers:    make(map[string]struct{}),
	}
	for _, sess := range registeredSessions {
		m.registeredSessions[sess] = struct{}{}
	}
	return m
}

func (w walletServiceMock) CreateProject(ctx context.Context, projectID uint64, name string, config *proto_wallet.ProjectWalletPreConfig, jwtAlg string, jwtSecret *string, jwtPublic *string) (*proto_wallet.Project, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) ProjectParentConfig(ctx context.Context, projectId uint64) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) ProjectParentWallet(ctx context.Context, projectId uint64) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) DeployProjectParentWallet(ctx context.Context, projectId uint64, chainID string) (string, string, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) ProjectWallets(ctx context.Context, projectId uint64, page *proto_wallet.Page) ([]*proto_wallet.ProjectWallet, *proto_wallet.Page, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) ProjectUserSalt(ctx context.Context, projectId uint64) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) ProjectWallet(ctx context.Context) (string, error) {
	return "0x00", nil
}

func (w walletServiceMock) SequenceContext(ctx context.Context) (*proto_wallet.MiniSequenceContext, error) {
	return &proto_wallet.MiniSequenceContext{}, nil
}

func (w walletServiceMock) UserSalt(ctx context.Context) (string, error) {
	return "0x00", nil
}

func (w walletServiceMock) UseHotWallet(ctx context.Context, walletAddress string) (bool, error) {
	return true, nil
}

func (w walletServiceMock) Wallets(ctx context.Context, page *proto_wallet.Page) ([]*proto_wallet.ProjectWallet, *proto_wallet.Page, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) IsValidMessageSignature(ctx context.Context, chainID uint64, walletAddress string, message string, signature string) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) GenTransaction(ctx context.Context, protoIntent *proto_wallet.Intent) (*proto_wallet.TransactionBundle, error) {
	intent := &intents.Intent{
		Version:   protoIntent.Version,
		Name:      intents.IntentName(protoIntent.Name),
		ExpiresAt: protoIntent.ExpiresAt,
		IssuedAt:  protoIntent.IssuedAt,
		Data:      protoIntent.Data,
	}
	intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataSendTransaction](intent)
	if err != nil {
		return nil, err
	}

	nonce, err := intentTyped.Data.Nonce()
	if err != nil {
		return nil, err
	}

	return &proto_wallet.TransactionBundle{
		ChainID: intentTyped.Data.Network,
		Nonce:   hexutil.EncodeBig(nonce),
		Transactions: []*proto_wallet.Transaction{
			{
				To:       "0x27CabC9700EE6Db2797b6AC1e1eCe81C72A2cD8D",
				Value:    "0x2000000000",
				GasLimit: "0x987654321",
				Data:     "0x010203",
			},
		},
	}, nil
}

func (w walletServiceMock) SendTransaction(ctx context.Context, intent *proto_wallet.Intent, result *proto_wallet.TransactionBundle, signatures []*proto_wallet.ProvidedSignature) (*proto_wallet.IntentResponse, error) {
	return &proto_wallet.IntentResponse{
		Code: "transactionReceipt",
		Data: map[string]any{
			"txHash": "0x123456",
		},
	}, nil
}

func (w walletServiceMock) SignMessage(ctx context.Context, intent *proto_wallet.Intent, message *proto_wallet.SignMessage, signatures []*proto_wallet.ProvidedSignature) (*proto_wallet.IntentResponse, error) {
	return &proto_wallet.IntentResponse{
		Code: "signedMessage",
		Data: map[string]any{
			"message":   "0x6D657373616765",
			"signature": "0x7369676E6174757265",
		},
	}, nil
}

func (w walletServiceMock) GetSession(ctx context.Context, sessionID string) (*proto_wallet.IntentResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (w *walletServiceMock) RegisterSession(ctx context.Context, userID string, protoIntent *proto_wallet.Intent) (*proto_wallet.IntentResponse, error) {
	intent := &intents.Intent{
		Version:   protoIntent.Version,
		Name:      intents.IntentName(protoIntent.Name),
		ExpiresAt: protoIntent.ExpiresAt,
		IssuedAt:  protoIntent.IssuedAt,
		Data:      protoIntent.Data,
	}
	intentTyped, err := intents.NewIntentTypedFromIntent[intents.IntentDataOpenSession](intent)
	if err != nil {
		return nil, err
	}

	w.registeredSessions[intentTyped.Data.SessionID] = struct{}{}
	w.registeredUsers[userID] = struct{}{}

	return &proto_wallet.IntentResponse{
		Code: string(proto.IntentResponseCode_sessionOpened),
	}, nil
}

func (w walletServiceMock) StartSessionValidation(ctx context.Context, walletAddress string, sessionID string, deviceMetadata string) (*proto_wallet.IntentResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (w *walletServiceMock) InvalidateSession(ctx context.Context, sessionID string) (bool, error) {
	if _, ok := w.registeredSessions[sessionID]; !ok {
		return false, fmt.Errorf("session does not exist")
	}
	delete(w.registeredSessions, sessionID)
	return true, nil
}

func (w walletServiceMock) SendIntent(ctx context.Context, intent *proto_wallet.Intent) (*proto_wallet.IntentResponse, error) {
	return &proto_wallet.IntentResponse{
		Code: "sentIntent",
		Data: map[string]any{
			"intent": intent,
		},
	}, nil
}

func (w walletServiceMock) ChainList(ctx context.Context) ([]*proto_wallet.Chain, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) FinishValidateSession(ctx context.Context, sessionId string, salt string, challenge string) (*proto_wallet.IntentResponse, error) {
	//TODO implement me
	panic("implement me")
}

var _ proto_wallet.WaaS = (*walletServiceMock)(nil)

type testTransport struct {
	http.RoundTripper
	modifyRequest func(req *http.Request)
}

func (tt testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"

	if tt.modifyRequest != nil {
		tt.modifyRequest(req)
	}

	return tt.RoundTripper.RoundTrip(req)
}

var _ http.RoundTripper = (*testTransport)(nil)

func getSentEmailMessage(t *testing.T, recipient string) (string, string, bool) {
	res, err := http.Get(fmt.Sprintf("%s/_aws/ses?email=noreply@local.auth.sequence.app", awsEndpoint))
	require.NoError(t, err)
	defer res.Body.Close()

	var result struct {
		Messages []struct {
			Destination struct {
				ToAddresses []string
			}
			Subject string
			Body    struct {
				HTML string `json:"html_part"`
			}
		}
	}

	require.NoError(t, json.NewDecoder(res.Body).Decode(&result))

	for _, msg := range result.Messages {
		for _, toAddress := range msg.Destination.ToAddresses {
			if toAddress == recipient {
				return msg.Subject, msg.Body.HTML, true
			}
		}
	}

	return "", "", false
}
