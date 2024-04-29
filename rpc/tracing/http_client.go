package tracing

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/semconv/v1.17.0/httpconv"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
	Get(string) (*http.Response, error)
}

type wrappedClient struct {
	HTTPClient
	ctx context.Context
}

func WrapClient(c HTTPClient) HTTPClient {
	return &wrappedClient{HTTPClient: c}
}

func WrapClientWithContext(ctx context.Context, c HTTPClient) HTTPClient {
	return &wrappedClient{HTTPClient: c, ctx: ctx}
}

func (c *wrappedClient) Do(req *http.Request) (res *http.Response, err error) {
	spanName := req.Method + " " + req.URL.Host
	if req.URL.Path != "/" {
		spanName += req.URL.Path
	}

	tracer := otel.Tracer(tracerName)
	ctx, span := tracer.Start(
		req.Context(),
		spanName,
		trace.WithAttributes(httpconv.ClientRequest(req)...),
		trace.WithAttributes(
			semconv.URLFull(req.URL.String()),
			semconv.URLScheme(req.URL.Scheme),
			semconv.URLPath(req.URL.Path),
			semconv.URLQuery(req.URL.RawQuery),
		),
		trace.WithSpanKind(trace.SpanKindClient),
	)
	defer func() {
		if err != nil {
			span.RecordError(err)
		} else {
			span.SetAttributes(httpconv.ClientResponse(res)...)
		}
		span.End()
	}()

	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
	return c.HTTPClient.Do(req.WithContext(ctx))
}

func (c *wrappedClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if c.ctx != nil {
		req = req.WithContext(c.ctx)
	}

	return c.Do(req)
}
