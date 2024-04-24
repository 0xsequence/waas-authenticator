package rpc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/goware/validation"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

type testContextKeyType string

const testContextKey testContextKeyType = "TESTCTX"

func testingMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := make(map[string]string)
		for k, vs := range r.Header {
			if len(vs) > 0 {
				values[strings.TrimPrefix(strings.ToLower(k), "-x-testctx-")] = vs[0]
			}
		}
		ctx := context.WithValue(r.Context(), testContextKey, values)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getTestingCtxValue(ctx context.Context, k string) string {
	values, ok := ctx.Value(testContextKey).(map[string]string)
	if !ok || values == nil {
		return ""
	}
	return values[strings.ToLower(k)]
}

func initRPC(cfg *config.Config, enc *enclave.Enclave, dbClient *dbMock) *rpc.RPC {
	svc := &rpc.RPC{
		Config:     cfg,
		HTTPClient: httpClient{},
		Enclave:    enc,
		Wallets:    newWalletServiceMock(nil),
		Tenants:    data.NewTenantTable(dbClient, "Tenants"),
		Sessions:   data.NewSessionTable(dbClient, "Sessions", "UserID-Index"),
		Accounts:   data.NewAccountTable(dbClient, "Accounts", data.AccountIndices{}),
	}
	return svc
}

func generateIntent(t *testing.T, name intents.IntentName, data any) *proto.Intent {
	return &proto.Intent{
		Version:    "1.0.0",
		Name:       proto.IntentName(name),
		ExpiresAt:  uint64(time.Now().Add(1 * time.Minute).Unix()),
		IssuedAt:   uint64(time.Now().Unix()),
		Data:       data,
		Signatures: nil,
	}
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

var (
	testPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwg8xlWTIwm44aLEqiA5lweHUSm2eeKwrTg3qEUhOVyGAo3eN
XRoD9wOHzjcvS8r/qfQdSdLA9p6IbSxV9LU2fXgYnT3IDhNuQ1rVkiIYqWqPWUn2
izUMJmbdVFRsgWi7/keXkslZD0DeKQM1R2QsCRZnPGHU3Jo/+2b6dTg8IRoBH2cq
rAPuynqBXYCC9+wNdYMQLA5vdaVzhFBASIVkMDDWlMaFgdOsISMHy9Klm0cXj3RE
02VsHcOQ1NRLY4Ddgpb5r0LUB0nfB4HMeK9plYqkkVF5BJihoGtGmebGuMqSFNgU
XflrxH152bHAZqqV+aIPIy2y4IdaQgP1VJrVKwIDAQABAoIBAQCQhtJNyh6+t2np
hrD/XYGpkPATcmqIwukJm9FMh8ZYnAn7NKmiwiJb0FRPX8gosYoRYE6D0aOGyPEg
Jdnqgx+O+GeUjBO3b/85yKewyxYE7ujN/gjRCnP/EbMbADlDc+Y27cjUOILMmmoa
r1n5zoABUJ8YWGA43+Rw7vPvYy9dEn1fbmsp850u/Grqdi0MUwIpQe9VKkVsYZ0n
HKAz+uY9Mhb/CsveD75cHrpaa5Ilfjkzo47Gah/+E6LB3/5wRjlzNzLMAQT449PW
yt2E/DYtVAR8uAtbfHB3cFcgNrWVg9IwU1G74SwqqwgQfpfEqKqsqG9BBXz0vwLT
o3vczVWZAoGBANJbz5+1XRlblmDV8MnVGoaHoylIA6+xE5iTiAUtopxfh3lMgTAh
sIepf7na0nkNPXFrR48Tkm29Y4f8EU2LY0a1t9WyAyufz9UTA4ABlHCuKztSqpG7
SgGEQvr/bAE61uN7JwVXGUICAR27OVfy7+iIOCzFDaOwhyfrE2XuP82VAoGBAOwq
DYedgoxuV63BWYDtvUt4olQbBCczJKyDirTGGdiPyQbsfE5eegcfZYxRkiCJ0Z5z
9OQlafIrok93kwkWgta2dj3onbXKLUviyGMSW1kGXoaTZu47rTZ7nxhqS5QeySGl
sHs/8j3+2UPHnwvLMlrMAOhIFQYrlFeQkxvIw+e/AoGAZh2Xjon2JccmGuAAQZon
hEL326RP1cv6HUkQ8KKUm6BsHWAcHodcMJ8Bl/E31vesahCP7k6r+IXFeU/N/ny5
tqukECKYE2dC9saCHnOl4YVLC0M39gKbDF1uPnYbsgUkJ82yxY7gfgCHFi26yozu
FU17J5CI7HtXQPOGuSaM5nkCgYEAqI4PIAbMYVxz2cDRF9MWsuIDwdGSckPvXe14
tzNYyRc+nGF3CxwlLiY7fR3PFMgow1XxqFAHwN9htiQa3nahpYuO8vqubUxCbhIL
gaJdbjm8h4J3CXuwUd2DnJJpJOugFBLE1gK664KUIOs92dYKN4G4+BBSaRf7hU/b
nw34vNMCgYBfG/VbQXT1WCcJgVycnU1hX7zmyzB/hk0xkmLR0nUzTgXMKOKUUXgX
2mD7U5VGZPYj7t8P+bz6/HEZqKmOoxFkXpsMPug34ZUWfjv3uCm7CFHtxA+BDT+5
cJEGAbCDYhyjvtjBLNy7YDQ1hdmCnqMxg/5AIwUMkvTTRg+qepfboA==
-----END RSA PRIVATE KEY-----`
)

func initConfig(t *testing.T) *config.Config {
	return &config.Config{
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
		KMS: config.KMSConfig{
			TenantKeys: []string{"TenantKey"},
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

type kmsMock struct {
	random io.Reader
}

func (m *kmsMock) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	out := &kms.DecryptOutput{
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
		KeyId:               aws.String("TenantKey"),
	}

	switch string(params.CiphertextBlob) {
	case "CiphertextForTenantKey":
		out.KeyId = aws.String("TenantKey")
	case "CiphertextForSessionKey":
		out.KeyId = aws.String("SessionKey")
	default:
		return nil, fmt.Errorf("invalid CiphertextBlob: %s", string(params.CiphertextBlob))
	}

	out.Plaintext, _ = base64.StdEncoding.DecodeString("RabEAhmjV3thObgGLjhJoza2jVDU0x4E8qHSL5MpsL4=")
	return out, nil
}

func (m *kmsMock) GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if params.KeyId == nil {
		return nil, fmt.Errorf("KeyId cannot be nil")
	}
	out := &kms.GenerateDataKeyOutput{KeyId: params.KeyId}

	switch *params.KeyId {
	case "TenantKey":
		out.CiphertextBlob = []byte("CiphertextForTenantKey")
	case "SessionKey":
		out.CiphertextBlob = []byte("CiphertextForSessionKey")
	default:
		return out, fmt.Errorf("invalid KeyId: %s", *params.KeyId)
	}
	out.Plaintext, _ = base64.StdEncoding.DecodeString("RabEAhmjV3thObgGLjhJoza2jVDU0x4E8qHSL5MpsL4=")
	return out, nil
}

type dbMock struct {
	tenants  map[uint64][]*data.Tenant
	sessions map[string]*data.Session
	accounts map[uint64]map[string]*data.Account
}

func (d *dbMock) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	if params.TableName == nil {
		return nil, fmt.Errorf("empty TableName")
	}

	switch *params.TableName {
	case "Sessions":
		idParam, ok := params.Key["ID"]
		if !ok {
			return nil, fmt.Errorf("must include an ID key")
		}
		idAttr, ok := idParam.(*dynamodbtypes.AttributeValueMemberS)
		if !ok {
			return nil, fmt.Errorf("ID key must be of type S")
		}
		if _, ok := d.sessions[idAttr.Value]; !ok {
			return nil, fmt.Errorf("session does not exist")
		}

		delete(d.sessions, idAttr.Value)

		out := &dynamodb.DeleteItemOutput{}
		return out, nil
	}

	return nil, fmt.Errorf("invalid TableName: %q", *params.TableName)
}

func (d *dbMock) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if params.TableName == nil {
		return nil, fmt.Errorf("empty TableName")
	}

	switch *params.TableName {
	case "Sessions":
		id, err := getDynamoAttribute[*dynamodbtypes.AttributeValueMemberS](params.Key, "ID")
		if err != nil {
			return nil, err
		}
		out := &dynamodb.GetItemOutput{}
		sess := d.sessions[id.Value]
		out.Item, err = attributevalue.MarshalMap(sess)
		if err != nil {
			return nil, err
		}
		return out, nil
	case "Accounts":
		projectAttr, err := getDynamoAttribute[*dynamodbtypes.AttributeValueMemberN](params.Key, "ProjectID")
		if err != nil {
			return nil, err
		}
		projectID, err := strconv.Atoi(projectAttr.Value)
		if err != nil {
			return nil, err
		}
		identity, err := getDynamoAttribute[*dynamodbtypes.AttributeValueMemberS](params.Key, "Identity")
		if err != nil {
			return nil, err
		}
		out := &dynamodb.GetItemOutput{}
		projectAccounts, ok := d.accounts[uint64(projectID)]
		if !ok {
			return out, nil
		}
		acc, ok := projectAccounts[identity.Value]
		if !ok {
			return out, nil
		}
		out.Item, err = attributevalue.MarshalMap(acc)
		if err != nil {
			return nil, err
		}
		return out, nil
	}

	return nil, fmt.Errorf("invalid TableName: %q", *params.TableName)
}

func (d *dbMock) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if params.TableName == nil {
		return nil, fmt.Errorf("empty TableName")
	}

	switch *params.TableName {
	case "Sessions":
		var sess data.Session
		if err := attributevalue.UnmarshalMap(params.Item, &sess); err != nil {
			return nil, err
		}
		d.sessions[sess.ID] = &sess
		return nil, nil
	case "Tenants":
		var tnt data.Tenant
		if err := attributevalue.UnmarshalMap(params.Item, &tnt); err != nil {
			return nil, err
		}
		d.tenants[tnt.ProjectID] = []*data.Tenant{&tnt}
		return nil, nil
	case "Accounts":
		var acc data.Account
		if err := attributevalue.UnmarshalMap(params.Item, &acc); err != nil {
			return nil, err
		}
		if _, ok := d.accounts[acc.ProjectID]; !ok {
			d.accounts[acc.ProjectID] = make(map[string]*data.Account)
		}
		d.accounts[acc.ProjectID][acc.Identity.String()] = &acc
		return nil, nil
	}

	return nil, fmt.Errorf("invalid TableName: %q", *params.TableName)
}

func (d *dbMock) Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if params.TableName == nil {
		return nil, fmt.Errorf("empty TableName")
	}

	switch *params.TableName {
	case "Sessions":
		userID, err := getDynamoAttribute[*dynamodbtypes.AttributeValueMemberS](params.ExpressionAttributeValues, ":userID")
		if err != nil {
			return nil, err
		}

		out := &dynamodb.QueryOutput{Items: make([]map[string]dynamodbtypes.AttributeValue, 0)}
		for _, sess := range d.sessions {
			if sess.UserID != userID.Value {
				continue
			}
			item, err := attributevalue.MarshalMap(sess)
			if err != nil {
				return nil, err
			}
			out.Items = append(out.Items, item)
		}
		return out, nil
	case "Tenants":
		idParam, ok := params.ExpressionAttributeValues[":id"]
		if !ok {
			return nil, fmt.Errorf("must include an :id expression attribute")
		}
		idAttr, ok := idParam.(*dynamodbtypes.AttributeValueMemberN)
		if !ok {
			return nil, fmt.Errorf("ProjectID key must be of type N")
		}

		idInt, _ := strconv.Atoi(idAttr.Value)
		versions, ok := d.tenants[uint64(idInt)]
		if !ok || len(versions) == 0 {
			return &dynamodb.QueryOutput{Items: nil}, nil
		}

		tnt := versions[len(versions)-1]
		item, err := attributevalue.MarshalMap(tnt)
		if err != nil {
			return nil, err
		}
		out := &dynamodb.QueryOutput{Items: []map[string]dynamodbtypes.AttributeValue{item}}
		return out, nil
	case "Accounts":
		pseParam, ok := params.ExpressionAttributeValues[":pse"]
		if !ok {
			return nil, fmt.Errorf("must include a :pse expression attribute")
		}
		pseParts := strings.Split(pseParam.(*dynamodbtypes.AttributeValueMemberS).Value, "|")
		projectID, _ := strconv.Atoi(pseParts[0])
		email := pseParts[1]

		projectAccounts := d.accounts[uint64(projectID)]
		out := &dynamodb.QueryOutput{Items: []map[string]dynamodbtypes.AttributeValue{}}
		for _, acc := range projectAccounts {
			if acc.Email == email {
				item, err := attributevalue.MarshalMap(acc)
				if err != nil {
					return nil, err
				}
				out.Items = append(out.Items, item)
			}
		}
		return out, nil
	}

	return nil, fmt.Errorf("invalid TableName: %q", *params.TableName)
}

func getDynamoAttribute[T dynamodbtypes.AttributeValue](attrVals map[string]dynamodbtypes.AttributeValue, name string) (T, error) {
	var zero T
	attr, ok := attrVals[name]
	if !ok {
		return zero, fmt.Errorf("must include key: %s", name)
	}
	value, ok := attr.(T)
	if !ok {
		return zero, fmt.Errorf("ID key must be of type %T", *new(T))
	}
	return value, nil
}

func newTenant(t *testing.T, enc *enclave.Enclave, issuer string) (*data.Tenant, *proto.TenantData) {
	att, err := enc.GetAttestation(context.Background(), nil)
	require.NoError(t, err)

	wallet, err := ethwallet.NewWalletFromRandomEntropy()
	require.NoError(t, err)

	userSalt, _ := hexutil.Decode("0xa176de7902ef0781d2c6120cc5fd5add3048e1543f597ef4feae38391d234839")
	payload := &proto.TenantData{
		ProjectID:     1,
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
		KMSKeys:        []string{"SessionKey"},
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(context.Background(), att, "TenantKey", payload)
	require.NoError(t, err)

	return &data.Tenant{
		ProjectID:    1,
		Version:      1,
		EncryptedKey: encryptedKey,
		Algorithm:    algorithm,
		Ciphertext:   ciphertext,
		CreatedAt:    time.Now(),
	}, payload
}

func newAccount(t *testing.T, enc *enclave.Enclave, issuer string, wallet *ethwallet.Wallet) *data.Account {
	att, err := enc.GetAttestation(context.Background(), nil)
	require.NoError(t, err)

	if wallet == nil {
		wallet, err = ethwallet.NewWalletFromRandomEntropy()
		require.NoError(t, err)
	}

	identity := proto.Identity{
		Type:    proto.IdentityType_OIDC,
		Issuer:  issuer,
		Subject: "SUBJECT",
	}
	payload := &proto.AccountData{
		ProjectID: 1,
		UserID:    fmt.Sprintf("%d|%s", 1, wallet.Address()),
		Identity:  identity.String(),
		CreatedAt: time.Now(),
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(context.Background(), att, "SessionKey", payload)
	require.NoError(t, err)

	return &data.Account{
		ProjectID:          1,
		Identity:           data.Identity(identity),
		UserID:             payload.UserID,
		Email:              "user@example.com",
		ProjectScopedEmail: "1|user@example.com",
		EncryptedKey:       encryptedKey,
		Algorithm:          algorithm,
		Ciphertext:         ciphertext,
		CreatedAt:          payload.CreatedAt,
	}

}

func newSessionFromData(t *testing.T, enc *enclave.Enclave, payload *proto.SessionData) *data.Session {
	att, err := enc.GetAttestation(context.Background(), nil)
	require.NoError(t, err)

	var identity proto.Identity
	require.NoError(t, identity.FromString(payload.Identity))

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(context.Background(), att, "SessionKey", payload)
	require.NoError(t, err)

	return &data.Session{
		ID:           payload.ID,
		ProjectID:    1,
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

func newSession(t *testing.T, enc *enclave.Enclave, issuer string, signingSession intents.Session) *data.Session {
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
		ProjectID: 1,
		UserID:    "1|USER",
		Identity:  identity.String(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	return newSessionFromData(t, enc, payload)
}

type walletServiceMock struct {
	registeredUsers    map[string]struct{}
	registeredSessions map[string]struct{}
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
		Code: "openedSession",
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

type httpClient struct{}

func (httpClient) Do(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	return http.DefaultClient.Do(req)
}

func (httpClient) Get(s string) (*http.Response, error) {
	if strings.HasPrefix(s, "https://") {
		s = "http://" + strings.TrimPrefix(s, "https://")
	}
	return http.DefaultClient.Get(s)
}

var _ rpc.HTTPClient = (*httpClient)(nil)
