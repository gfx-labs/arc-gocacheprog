// Package telemetry sets up OpenTelemetry tracing and metrics from the
// standard OTEL_* environment variables.
package telemetry

import (
	"context"
	"errors"
	"os"
	"time"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// Setup installs global tracer and meter providers. Exporters are chosen by
// OTEL_TRACES_EXPORTER and OTEL_METRICS_EXPORTER (otlp, console, prometheus,
// none). When neither those nor OTEL_EXPORTER_OTLP_ENDPOINT is set, nothing
// is exported. The returned function flushes and stops the providers.
func Setup(ctx context.Context, service, version string) (func(context.Context) error, error) {
	if os.Getenv("OTEL_SDK_DISABLED") == "true" {
		return func(context.Context) error { return nil }, nil
	}
	defaultNone()

	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName(service), semconv.ServiceVersion(version)))
	if err != nil {
		return nil, err
	}
	res, err = resource.Merge(res, envResource(ctx))
	if err != nil {
		return nil, err
	}

	spans, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		return nil, err
	}
	var tpOpts []sdktrace.TracerProviderOption
	tpOpts = append(tpOpts, sdktrace.WithResource(res))
	if !autoexport.IsNoneSpanExporter(spans) {
		tpOpts = append(tpOpts, sdktrace.WithBatcher(spans))
	}
	tp := sdktrace.NewTracerProvider(tpOpts...)

	reader, err := autoexport.NewMetricReader(ctx)
	if err != nil {
		tp.Shutdown(ctx) //nolint:errcheck
		return nil, err
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(reader))

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))

	if err := runtime.Start(runtime.WithMeterProvider(mp), runtime.WithMinimumReadMemStatsInterval(15*time.Second)); err != nil {
		tp.Shutdown(ctx) //nolint:errcheck
		mp.Shutdown(ctx) //nolint:errcheck
		return nil, err
	}

	return func(ctx context.Context) error {
		return errors.Join(tp.Shutdown(ctx), mp.Shutdown(ctx))
	}, nil
}

// defaultNone sets the exporters to none unless the environment configures
// them, so an unconfigured server does not retry exports to localhost.
func defaultNone() {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		return
	}
	for _, k := range []struct{ kind, endpoint string }{
		{"OTEL_TRACES_EXPORTER", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"},
		{"OTEL_METRICS_EXPORTER", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"},
	} {
		if os.Getenv(k.kind) == "" && os.Getenv(k.endpoint) == "" {
			os.Setenv(k.kind, "none") //nolint:errcheck
		}
	}
}

// envResource reads OTEL_RESOURCE_ATTRIBUTES and OTEL_SERVICE_NAME, which
// override the defaults.
func envResource(ctx context.Context) *resource.Resource {
	r, err := resource.New(ctx, resource.WithFromEnv(), resource.WithHost(), resource.WithProcessRuntimeVersion())
	if err != nil {
		return resource.Empty()
	}
	return r
}
