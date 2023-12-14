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
	"github.com/0xsequence/go-sequence/intents/packets"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/0xsequence/waas-authenticator/rpc/crypto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
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
	}
}

func issueAccessTokenAndRunJwksServer(t *testing.T) (iss string, tok string, close func()) {
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

	tokRaw, err := jwt.NewBuilder().
		Issuer(jwksServer.URL).
		Subject("subject").
		Build()
	require.NoError(t, err)
	tokBytes, err := jwt.Sign(tokRaw, jwt.WithKey(jwa.RS256, jwtKey))
	require.NoError(t, err)

	return jwksServer.URL, string(tokBytes), jwksServer.Close
}

type kmsMock struct {
	random             io.Reader
	timesCalledDecrypt int
}

func (m *kmsMock) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	out := &kms.DecryptOutput{
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
		KeyId:               aws.String("TransportKey"),
	}

	switch m.timesCalledDecrypt {
	case 0:
		out.KeyId = aws.String("TenantKey")
	case 1:
		out.KeyId = aws.String("TransportKey")
	case 2:
		out.KeyId = aws.String("SessionKey")
	}

	if r := params.Recipient; r != nil {
		out.CiphertextForRecipient, _ = base64.StdEncoding.DecodeString("MIAGCSqGSIb3DQEHA6CAMIACAQIxggFrMIIBZwIBAoAgljGgxlmRCtWqvB/s/Aw+ZNTDlc6Uka86SLVmlNmFGAMwPAYJKoZIhvcNAQEHMC+gDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAASCAQAnkM/kUE5xxRRdFeIen3JFsc8jJcM7xn4mlEZL4MKdQmuUjyVg9qE9IXuR8CDRWcpNATSFINy8/ttd9mOu94vHAWKe+YsM3mckLsPMIhXl7mrZAYASZSyzu6bAeGbqZw1PRyNGz8yWWBzlJM0+kdToqZZ68dyzbLAA6x5gjbJlCYMI13MOvmrvPp2LiF5fZEMSzr1ZF2ZsR7zduRKnbq2QlPoeRX/ZFGQ438ohYQpzBDfNDUrOz14KjgziWS7NE3qhmnaNHsQNBBupGc68X1Uhoq+/WZn6MgSatW/W22R0n5Z02+DDw2Mw7JwVc6dyheN4odDnP/HSJ5wR2pjZcFqlMIAGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEOOdJUsisyEkuWxUsJIxzgSggAQwC73Sq5rDaXSSFSJUKzTqrt0zdhL3Q2NtxOeIDSqvoOaS3vrbNH1d9gd7KUxJEafRAAAAAAAAAAAAAA==")
	} else {
		out.Plaintext, _ = base64.StdEncoding.DecodeString("RabEAhmjV3thObgGLjhJoza2jVDU0x4E8qHSL5MpsL4=")
	}
	m.timesCalledDecrypt++
	return out, nil
}

func (m *kmsMock) GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if params.KeyId == nil {
		return nil, fmt.Errorf("KeyId cannot be nil")
	}
	out := &kms.GenerateDataKeyOutput{KeyId: params.KeyId}
	out.CiphertextBlob, _ = base64.StdEncoding.DecodeString("AQIDAHhSsN44C1VwetR6+sdkuCGqaJVquI96Ub9aSpCc8cM07gFkz2ECg6joWCrwlCamP+KuAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMuoJXIPF0RaIeZnI8AgEQgDtbMeqiQ5fEU8KkKPlzKeqCW88htk1HNGSufo3ZrThcwNmIFnOgy+YbM3BwvxVTYssoORrW6eSJDFAvzQ==")
	if r := params.Recipient; r != nil {
		out.CiphertextForRecipient, _ = base64.StdEncoding.DecodeString("MIAGCSqGSIb3DQEHA6CAMIACAQIxggFrMIIBZwIBAoAgljGgxlmRCtWqvB/s/Aw+ZNTDlc6Uka86SLVmlNmFGAMwPAYJKoZIhvcNAQEHMC+gDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAASCAQCicFA+nY1HTguzHcWR19Y7t9DPfSM3ca3u8auoIf2SstjKacCGpmxNazvEk/tcOaU2G8hzoC2i5lTvfrficEh36IxDIEzV1DnawdyfFmniSGpkP/ORXXg7Dij5truDtf71AOmEmHAUWLzFOXqQ0VdZ2lHVaAsapwq+3rv4G/0HCwlh33CakQzWy8u9az1vy4IRuS8LJjjZ/JLGPxz0uF3301WAMRUTjdU/u4phJv2TbvkXvZG8faIajk27x8AKjSnLy7P/B2Zi3RrJH+PPTlmwXjpBOtFwv8MjM/FcmerHd0utYn+jdnrqs+84eTtM220RyArZ8C/LYxQ0//IEl259MIAGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEDOrR/kQEWdbYa/9rnGGEhmggAQww9uq+DOprZws+LFTRMGB8mW1guIaB1Jy6F3rbCpxjTjnR8Ov7RNmoFlHGAsbATWAAAAAAAAAAAAAAA==")
	} else {
		out.Plaintext, _ = base64.StdEncoding.DecodeString("RabEAhmjV3thObgGLjhJoza2jVDU0x4E8qHSL5MpsL4=")
	}
	return out, nil
}

type dbMock struct {
	tenants  map[uint64][]*data.Tenant
	sessions map[string]*data.Session
}

func (d *dbMock) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	panic("implement me")
}

func (d *dbMock) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
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
		out := &dynamodb.GetItemOutput{}
		acc := d.sessions[idAttr.Value]
		if !ok {
			return out, nil
		}
		var err error
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
	}

	return nil, fmt.Errorf("invalid TableName: %q", *params.TableName)
}

func (d *dbMock) Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if params.TableName == nil {
		return nil, fmt.Errorf("empty TableName")
	}

	switch *params.TableName {
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
			return nil, fmt.Errorf("tenant does not exist: %q", idAttr.Value)
		}

		tnt := versions[len(versions)-1]
		item, err := attributevalue.MarshalMap(tnt)
		if err != nil {
			return nil, err
		}
		out := &dynamodb.QueryOutput{Items: []map[string]dynamodbtypes.AttributeValue{item}}
		return out, nil
	}

	return nil, fmt.Errorf("invalid TableName: %q", *params.TableName)
}

func newTenant(t *testing.T, enc *enclave.Enclave, issuer string) *data.Tenant {
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
		OIDCProviders:   []*proto.OpenIdProvider{{Issuer: issuer}},
		TransportKeys:   []string{"TransportKey"},
		SessionKeys:     []string{"SessionKey"},
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
	}
}

func newSession(t *testing.T, enc *enclave.Enclave, issuer string, wallet *ethwallet.Wallet) *data.Session {
	att, err := enc.GetAttestation(context.Background(), nil)
	require.NoError(t, err)

	payload := &proto.SessionData{
		Address:   wallet.Address(),
		ProjectID: 1,
		Issuer:    issuer,
		Subject:   "SUBJECT",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	encryptedKey, algorithm, ciphertext, err := crypto.EncryptData(context.Background(), att, "SessionKey", payload)
	require.NoError(t, err)

	return &data.Session{
		ID:           wallet.Address().String(),
		ProjectID:    1,
		UserID:       fmt.Sprintf("%d#%s#%s", payload.ProjectID, payload.Issuer, payload.Subject),
		FriendlyName: "FriendlyName",
		EncryptedKey: encryptedKey,
		Algorithm:    algorithm,
		Ciphertext:   ciphertext,
		RefreshedAt:  time.Now(),
		CreatedAt:    time.Now(),
	}
}

type walletServiceMock struct{}

func (w walletServiceMock) CreatePartner(ctx context.Context, name string, config *proto_wallet.PartnerWalletPreConfig, jwtAlg string, jwtSecret *string, jwtPublic *string) (*proto_wallet.Partner, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) PartnerParentConfig(ctx context.Context, partnerId uint64) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) PartnerParentWallet(ctx context.Context, partnerId uint64) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) DeployPartnerParentWallet(ctx context.Context, partnerId uint64, chainID uint64) (string, string, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) PartnerWallets(ctx context.Context, partnerId uint64, page *proto_wallet.Page) ([]*proto_wallet.PartnerWallet, *proto_wallet.Page, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) PartnerUserSalt(ctx context.Context, partnerId uint64) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) ParentWallet(ctx context.Context) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) SequenceContext(ctx context.Context) (*proto_wallet.MiniSequenceContext, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) UserSalt(ctx context.Context) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) UseHotWallet(ctx context.Context, walletAddress string) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) Wallets(ctx context.Context, page *proto_wallet.Page) ([]*proto_wallet.PartnerWallet, *proto_wallet.Page, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) IsValidMessageSignature(ctx context.Context, chainID uint64, walletAddress string, message string, signature string) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) GenTransaction(ctx context.Context, payload string) (*proto_wallet.TransactionBundle, error) {
	var intent intents.Intent
	if err := json.Unmarshal([]byte(payload), &intent); err != nil {
		return nil, err
	}
	var packet packets.SendTransactionsPacket
	if err := json.Unmarshal(intent.Packet, &packet); err != nil {
		return nil, err
	}

	nonce, err := packet.Nonce()
	if err != nil {
		return nil, err
	}

	return &proto_wallet.TransactionBundle{
		ChainID: packet.Network,
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

func (w walletServiceMock) SendTransaction(ctx context.Context, wallet *proto_wallet.TargetWallet, payload string, result *proto_wallet.TransactionBundle, signatures []*proto_wallet.ProvidedSignature) (*proto_wallet.PayloadResponse, error) {
	return &proto_wallet.PayloadResponse{
		Code: "transactionReceipt",
		Data: map[string]any{
			"txHash": "0x123456",
		},
	}, nil
}

func (w walletServiceMock) SignMessage(ctx context.Context, wallet *proto_wallet.TargetWallet, payload string, message *proto_wallet.SignMessage, signatures []*proto_wallet.ProvidedSignature) (*proto_wallet.PayloadResponse, error) {
	return &proto_wallet.PayloadResponse{
		Code: "signedMessage",
		Data: map[string]any{
			"message":   "0x6D657373616765",
			"signature": "0x7369676E6174757265",
		},
	}, nil
}

func (w walletServiceMock) GetSession(ctx context.Context, sessionAddress string) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) RegisterSession(ctx context.Context, userID string, sessionPayload string) (*proto_wallet.PayloadResponse, error) {
	return &proto_wallet.PayloadResponse{}, nil
}

func (w walletServiceMock) StartSessionValidation(ctx context.Context, walletAddress string, sessionAddress string, deviceMetadata string, redirectUrl *string) (*proto_wallet.PayloadResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) InvalidateSession(ctx context.Context, sessionAddress string) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) SendIntent(ctx context.Context, wallet *proto_wallet.TargetWallet, payload string) (*proto_wallet.PayloadResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (w walletServiceMock) ChainList(ctx context.Context) ([]*proto_wallet.Chain, error) {
	//TODO implement me
	panic("implement me")
}

var _ proto_wallet.Wallet = (*walletServiceMock)(nil)
