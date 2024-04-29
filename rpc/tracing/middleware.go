package tracing

import (
	"net/http"

	"github.com/go-chi/traceid"
	"github.com/riandyrn/otelchi"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: replace otelchi with custom tracing implementation
			otelmw := otelchi.Middleware("WaasAuthenticator")(decorateSpanMiddleware(next))
			otelmw.ServeHTTP(w, r)
		})
	}
}

func decorateSpanMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tid := traceid.FromContext(r.Context())
		span := trace.SpanFromContext(r.Context())
		span.SetAttributes(
			attribute.String("sequence.traceid", tid),
			semconv.NetHostName(r.Host),
			semconv.ServerAddress(r.Host),
			semconv.HTTPTarget(r.URL.Path),
			semconv.URLPath(r.URL.Path),
			semconv.URLQuery(r.URL.RawQuery),
		)

		next.ServeHTTP(w, r)
	})
}
