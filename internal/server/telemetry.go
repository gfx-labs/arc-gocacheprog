package server

import (
	"context"
	"net/http"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/gfx-labs/arc-gocacheprog/internal/api"
)

const instrumentationName = "github.com/gfx-labs/arc-gocacheprog/internal/server"

var tracer = otel.Tracer(instrumentationName)

// metrics are the cache-specific instruments. HTTP request metrics come
// from otelhttp, database metrics from otelpgx and S3 spans from otelaws.
type metrics struct {
	lookups        metric.Int64Counter
	uploads        metric.Int64Counter
	uploadBytes    metric.Int64Counter
	downloadBytes  metric.Int64Counter
	links          metric.Int64Counter
	rejections     metric.Int64Counter
	uploadsActive  metric.Int64UpDownCounter
	gcRuns         metric.Int64Counter
	gcRemoved      metric.Int64Counter
	gcRemovedBytes metric.Int64Counter
	gcDuration     metric.Float64Histogram
}

func newMetrics() *metrics {
	m := otel.Meter(instrumentationName)
	var ms metrics
	// Errors only occur for invalid instrument names, which are constant.
	ms.lookups, _ = m.Int64Counter("gocache.lookups",
		metric.WithDescription("Entry lookups by result: hit, miss, or error."))
	ms.uploads, _ = m.Int64Counter("gocache.uploads",
		metric.WithDescription("Uploads that reached storage, by result: stored, deduplicated, or error."))
	ms.uploadBytes, _ = m.Int64Counter("gocache.upload.size", metric.WithUnit("By"),
		metric.WithDescription("Bytes received in stored or deduplicated uploads."))
	ms.downloadBytes, _ = m.Int64Counter("gocache.download.size", metric.WithUnit("By"),
		metric.WithDescription("Bytes sent for cache hits."))
	ms.links, _ = m.Int64Counter("gocache.links",
		metric.WithDescription("Link requests that reached storage, by result: linked, missing, or error."))
	ms.rejections, _ = m.Int64Counter("gocache.rejections",
		metric.WithDescription("Requests rejected before storage, by reason."))
	ms.uploadsActive, _ = m.Int64UpDownCounter("gocache.uploads.active",
		metric.WithDescription("Uploads holding a concurrency slot."))
	ms.gcRuns, _ = m.Int64Counter("gocache.gc.runs",
		metric.WithDescription("GC passes by result: done, skipped, or error."))
	ms.gcRemoved, _ = m.Int64Counter("gocache.gc.removed",
		metric.WithDescription("Items removed by GC, by kind: expired, evicted, blob, orphan."))
	ms.gcRemovedBytes, _ = m.Int64Counter("gocache.gc.removed.size", metric.WithUnit("By"),
		metric.WithDescription("Blob bytes removed by GC."))
	ms.gcDuration, _ = m.Float64Histogram("gocache.gc.duration", metric.WithUnit("s"),
		metric.WithDescription("Duration of GC passes that ran."))
	return &ms
}

func resultAttr(v string) metric.MeasurementOption {
	return metric.WithAttributeSet(attribute.NewSet(attribute.String("result", v)))
}

// Rejection reasons. A fixed set keeps metric cardinality bounded.
const (
	rejectAuth        = "auth"
	rejectBadRequest  = "bad_request"
	rejectNoScope     = "no_scope"
	rejectRateLimit   = "request_rate"
	rejectWriteLimit  = "write_rate"
	rejectUploadSlots = "upload_slots"
	rejectHashCheck   = "hash_mismatch"
)

func (m *metrics) reject(ctx context.Context, reason string) {
	m.rejections.Add(ctx, 1, metric.WithAttributeSet(attribute.NewSet(attribute.String("reason", reason))))
}

// instrument wraps h with otelhttp for a server span and the standard
// http.server metrics. Health checks are not traced.
func instrument(h http.Handler) http.Handler {
	return otelhttp.NewHandler(h, "gocache",
		// CI jobs are not trusted to pick our trace IDs. Their context is
		// kept as a link.
		otelhttp.WithPublicEndpointFn(func(*http.Request) bool { return true }),
		otelhttp.WithFilter(func(r *http.Request) bool { return r.URL.Path != api.PathHealthz }),
	)
}

// setRoute names the server span and labels HTTP metrics with the route.
// pattern is a ServeMux pattern such as "GET /v1/actions/{id}".
func setRoute(ctx context.Context, pattern string) {
	if pattern == "" {
		return
	}
	_, route, ok := strings.Cut(pattern, " ")
	if !ok {
		route = pattern
	}
	span := trace.SpanFromContext(ctx)
	span.SetName(pattern)
	span.SetAttributes(semconv.HTTPRoute(route))
	if l, ok := otelhttp.LabelerFromContext(ctx); ok {
		l.Add(semconv.HTTPRoute(route))
	}
}

func endSpan(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}
