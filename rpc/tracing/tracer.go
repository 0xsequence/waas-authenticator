package tracing

import (
	"context"

	"github.com/0xsequence/go-sequence/intents"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/0xsequence/waas-authenticator/rpc/tracing"

func Intent(ctx context.Context, intent *intents.Intent) (context.Context, trace.Span) {
	tracer := otel.Tracer(tracerName)
	return tracer.Start(ctx, "Intent."+intent.Name, trace.WithSpanKind(trace.SpanKindInternal))
}

func Span(ctx context.Context, name string) (context.Context, trace.Span) {
	tracer := otel.Tracer(tracerName)
	return tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindInternal))
}
