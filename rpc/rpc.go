package rpc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/0xsequence/nitrocontrol/enclave"
	waasauthenticator "github.com/0xsequence/waas-authenticator"
	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/data"
	"github.com/0xsequence/waas-authenticator/proto"
	proto_wallet "github.com/0xsequence/waas-authenticator/proto/waas"
	"github.com/0xsequence/waas-authenticator/rpc/access"
	"github.com/0xsequence/waas-authenticator/rpc/attestation"
	"github.com/0xsequence/waas-authenticator/rpc/awscreds"
	"github.com/0xsequence/waas-authenticator/rpc/tenant"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httplog"
	"github.com/go-chi/telemetry"
	"github.com/rs/zerolog"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
	Get(string) (*http.Response, error)
}

type RPC struct {
	Config     *config.Config
	Log        zerolog.Logger
	Server     *http.Server
	HTTPClient HTTPClient
	Enclave    *enclave.Enclave
	Tenants    *data.TenantTable
	Sessions   *data.SessionTable
	Accounts   *data.AccountTable
	Wallets    proto_wallet.WaaS

	measurements *enclave.Measurements
	startTime    time.Time
	running      int32
}

func New(cfg *config.Config, client HTTPClient) (*RPC, error) {
	if client == nil {
		client = http.DefaultClient
	}

	options := []func(options *awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithHTTPClient(client),
		awsconfig.WithCredentialsProvider(awscreds.NewProvider(client, cfg.Endpoints.MetadataServer)),
	}

	if cfg.Endpoints.AWSEndpoint != "" {
		options = append(options, awsconfig.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{URL: cfg.Endpoints.AWSEndpoint}, nil
			}),
		), awsconfig.WithCredentialsProvider(&awscreds.StaticProvider{
			AccessKeyID:     "test",
			SecretAccessKey: "test",
			SessionToken:    "test",
		}))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), options...)
	if err != nil {
		return nil, err
	}

	httpServer := &http.Server{
		ReadTimeout:       45 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       45 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	enclaveProvider := enclave.DummyProvider
	if cfg.Service.UseNSM {
		enclaveProvider = enclave.NitroProvider
	}
	enc, err := enclave.New(context.Background(), enclaveProvider, kms.NewFromConfig(awsCfg))
	if err != nil {
		return nil, err
	}

	m, err := enc.GetMeasurements(context.Background())
	if err != nil {
		return nil, err
	}

	db := dynamodb.NewFromConfig(awsCfg)
	s := &RPC{
		Log: httplog.NewLogger("waas-authenticator", httplog.Options{
			LogLevel: zerolog.LevelDebugValue,
		}),
		Config:     cfg,
		Server:     httpServer,
		HTTPClient: client,
		Enclave:    enc,
		Tenants:    data.NewTenantTable(db, cfg.Database.TenantsTable),
		Sessions:   data.NewSessionTable(db, cfg.Database.SessionsTable, "UserID-Index"),
		Accounts: data.NewAccountTable(db, cfg.Database.AccountsTable, data.AccountIndices{
			ByUserID: "UserID-Index",
			ByEmail:  "Email-Index",
		}),
		Wallets:      proto_wallet.NewWaaSClient(cfg.Endpoints.WaasAPIServer, client),
		startTime:    time.Now(),
		measurements: m,
	}
	return s, nil
}

func (s *RPC) Run(ctx context.Context, l net.Listener) error {
	if s.IsRunning() {
		return fmt.Errorf("rpc: already running")
	}

	s.Log.Info().
		Str("op", "run").
		Str("ver", waasauthenticator.VERSION).
		Msgf("-> rpc: started enclave")

	atomic.StoreInt32(&s.running, 1)
	defer atomic.StoreInt32(&s.running, 0)

	// Setup HTTP server handler
	s.Server.Handler = s.Handler()

	// Handle stop signal to ensure clean shutdown
	go func() {
		<-ctx.Done()
		s.Stop(context.Background())
	}()

	// Start the http server and serve!
	err := s.Server.Serve(l)
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *RPC) Stop(timeoutCtx context.Context) {
	if !s.IsRunning() || s.IsStopping() {
		return
	}
	atomic.StoreInt32(&s.running, 2)

	s.Log.Info().Str("op", "stop").Msg("-> rpc: stopping..")
	s.Server.Shutdown(timeoutCtx)
	s.Log.Info().Str("op", "stop").Msg("-> rpc: stopped.")
}

func (s *RPC) IsRunning() bool {
	return atomic.LoadInt32(&s.running) == 1
}

func (s *RPC) IsStopping() bool {
	return atomic.LoadInt32(&s.running) == 2
}

func (s *RPC) Handler() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)

	// Metrics and heartbeat
	r.Use(telemetry.Collector(s.Config.Telemetry, []string{"/rpc"}))
	r.Use(middleware.NoCache)
	r.Use(middleware.Heartbeat("/ping"))

	// HTTP request logger
	r.Use(httplog.RequestLogger(s.Log, []string{"/", "/ping", "/status", "/favicon.ico"}))

	// Timeout any request after 28 seconds as Cloudflare has a 30 second limit anyways.
	r.Use(middleware.Timeout(28 * time.Second))

	// CORS
	corsOptions := cors.Options{
		AllowedOrigins: []string{"https://*"},
		AllowedMethods: []string{"POST", "OPTIONS"},
		AllowedHeaders: []string{
			// TODO: in future we can remove "X-Sequence-Tenant" as its replaced by "X-Access-Key"
			"Accept", "Authorization", "Content-Type", "X-Attestation-Nonce", "X-Sequence-Tenant", "X-Access-Key",
		},
		AllowCredentials: true,
		MaxAge:           600,
	}
	if s.Config.Mode != config.ProductionMode {
		corsOptions.AllowedOrigins = append(corsOptions.AllowedOrigins, "http://*")
	}

	c := cors.New(corsOptions)
	r.Use(c.Handler)

	// Quick pages
	r.Use(middleware.PageRoute("/", http.HandlerFunc(indexHandler)))
	r.Use(middleware.PageRoute("/status", http.HandlerFunc(s.statusHandler)))
	r.Use(middleware.PageRoute("/favicon.ico", http.HandlerFunc(emptyHandler)))

	userRouter := r.Group(func(r chi.Router) {
		// Generate attestation document
		r.Use(attestation.Middleware(s.Enclave))

		// Find and decrypt tenant data
		r.Use(tenant.Middleware(s.Tenants, s.Config.KMS.TenantKeys))
	})
	userRouter.Handle("/rpc/WaasAuthenticator/*", proto.NewWaasAuthenticatorServer(s))

	adminRouter := r.Group(func(r chi.Router) {
		// Validate admin JWTs
		r.Use(access.JWTAuthMiddleware(s.Config.Admin))

		// Generate attestation document
		r.Use(attestation.Middleware(s.Enclave))
	})
	adminRouter.Handle("/rpc/WaasAuthenticatorAdmin/*", proto.NewWaasAuthenticatorAdminServer(s))

	if s.Config.Service.DebugProfiler {
		r.Mount("/debug", middleware.Profiler())
	}

	return r
}

// Ping is a healthcheck that returns an empty message.
func (s *RPC) Ping(ctx context.Context) (bool, error) {
	return true, nil
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("."))
}

func emptyHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(""))
}
