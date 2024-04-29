package tracing

import (
	"fmt"
	"slices"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

func SampleRoutes(routes ...string) sdktrace.Sampler {
	return routeSampler{
		routes: routes,
	}
}

type routeSampler struct {
	routes []string
}

func (rs routeSampler) ShouldSample(p sdktrace.SamplingParameters) sdktrace.SamplingResult {
	res := sdktrace.SamplingResult{
		Decision:   sdktrace.Drop,
		Tracestate: trace.SpanContextFromContext(p.ParentContext).TraceState(),
	}

	attrs := attribute.NewSet(p.Attributes...)
	routeVal, ok := attrs.Value(semconv.HTTPRouteKey)
	if ok && slices.Contains(rs.routes, routeVal.AsString()) {
		res.Decision = sdktrace.RecordAndSample
	}

	return res
}

func (rs routeSampler) Description() string {
	return fmt.Sprintf("RouteSampler{%s}", strings.Join(rs.routes, ","))
}
