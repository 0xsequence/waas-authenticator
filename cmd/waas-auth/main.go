package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	waasauthenticator "github.com/0xsequence/waas-authenticator"
	"github.com/0xsequence/waas-authenticator/config"
	"github.com/0xsequence/waas-authenticator/rpc"
	"github.com/go-chi/traceid"
	"github.com/go-chi/transport"
	"github.com/mdlayher/vsock"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		panic(err)
	}

	baseTransport := http.DefaultTransport
	if cfg.Service.VSock {
		baseTransport = &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return url.Parse("http://vsock-proxy")
			},
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				log.Printf("Outgoing connection to %s://%s\n", network, addr)
				return vsock.Dial(3, cfg.Service.ProxyPort, nil)
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	// HTTP client to use for all outgoing connections out of the enclave
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: transport.Chain(
			baseTransport,
			transport.SetHeader("User-Agent", "waas-authenticator/"+waasauthenticator.VERSION),
			traceid.Transport,
		),
	}

	s, err := rpc.New(cfg, client)
	if err != nil {
		panic(err)
	}
	defer s.Stop(context.Background())

	// Listen on a VSOCK if enabled
	var l net.Listener
	if cfg.Service.VSock {
		l, err = vsock.Listen(cfg.Service.EnclavePort, nil)
	} else {
		l, err = net.Listen("tcp", fmt.Sprintf(":%d", cfg.Service.EnclavePort))
	}
	if err != nil {
		panic(err)
	}

	if err := s.Run(context.Background(), l); err != nil {
		panic(err)
	}
}
