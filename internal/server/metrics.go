// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aquitano/aqt-sync/internal/api"
)

// Metrics owns the server's Prometheus registry and instruments. Everything here
// is operational metadata — request counts, byte volumes, per-account storage
// totals keyed by opaque owner handle — never content, names, or emails, so the
// zero-knowledge posture is unchanged. The handler is not mounted on the API
// router; the binary serves it on a separate listener (AQT_METRICS_ADDR) that a
// deployment keeps on a loopback or private interface.
type Metrics struct {
	registry *prometheus.Registry

	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec

	packBytesIn       prometheus.Counter
	packBytesOut      prometheus.Counter
	publicObjectBytes prometheus.Counter
	grantObjectBytes  prometheus.Counter
	grantWrites       prometheus.Counter

	gcRuns           *prometheus.CounterVec
	gcPacksDeleted   prometheus.Counter
	gcBytesFreed     prometheus.Counter
	gcPacksRepacked  prometheus.Counter
	gcBytesReclaimed prometheus.Counter
}

func newMetrics(store *Store) *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aqt_http_requests_total",
			Help: "HTTP requests by method, matched route, and status code (410s and 426s land here).",
		}, []string{"method", "route", "status"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "aqt_http_request_duration_seconds",
			Help:    "HTTP request latency by method and matched route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
		packBytesIn: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aqt_pack_bytes_received_total",
			Help: "Raw pack bytes accepted by PUT /v1/packs/:id.",
		}),
		packBytesOut: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aqt_pack_bytes_served_total",
			Help: "Pack bytes served by GET /v1/packs/:id (after Range slicing).",
		}),
		publicObjectBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aqt_public_object_bytes_served_total",
			Help: "Bytes served by the unauthenticated public object-slice endpoint.",
		}),
		grantObjectBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aqt_grant_object_bytes_served_total",
			Help: "Bytes served by the authenticated grant object-slice endpoint.",
		}),
		grantWrites: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aqt_grant_writes_total",
			Help: "Grants created or re-wrapped via POST /v1/resources/:id/grants.",
		}),
		gcRuns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aqt_gc_runs_total",
			Help: "GC sweeps by trigger (client POST /v1/gc vs the scheduled timer).",
		}, []string{"trigger"}),
		gcPacksDeleted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aqt_gc_packs_deleted_total",
			Help: "Fully-dead packs deleted by GC.",
		}),
		gcBytesFreed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aqt_gc_bytes_freed_total",
			Help: "Bytes freed by deleting fully-dead packs.",
		}),
		gcPacksRepacked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aqt_gc_packs_repacked_total",
			Help: "Partially-dead packs compacted by GC.",
		}),
		gcBytesReclaimed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aqt_gc_bytes_reclaimed_total",
			Help: "Bytes reclaimed by repacking partially-dead packs.",
		}),
	}
	m.registry.MustRegister(
		m.requests, m.duration,
		m.packBytesIn, m.packBytesOut, m.publicObjectBytes, m.grantObjectBytes, m.grantWrites,
		m.gcRuns, m.gcPacksDeleted, m.gcBytesFreed, m.gcPacksRepacked, m.gcBytesReclaimed,
		&accountCollector{store: store},
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// middleware records every request against its matched route pattern
// (c.FullPath), so the label set stays bounded by the route table no matter what
// paths clients probe; unmatched requests share one bucket.
func (m *Metrics) middleware(c *gin.Context) {
	start := time.Now()
	c.Next()
	route := c.FullPath()
	if route == "" {
		route = "unmatched"
	}
	m.requests.WithLabelValues(c.Request.Method, route, strconv.Itoa(c.Writer.Status())).Inc()
	m.duration.WithLabelValues(c.Request.Method, route).Observe(time.Since(start).Seconds())
}

func (m *Metrics) observeGC(trigger string, res api.GCResponse) {
	m.gcRuns.WithLabelValues(trigger).Inc()
	m.gcPacksDeleted.Add(float64(res.DeletedPacks))
	m.gcBytesFreed.Add(float64(res.FreedBytes))
	m.gcPacksRepacked.Add(float64(res.RepackedPacks))
	m.gcBytesReclaimed.Add(float64(res.ReclaimedBytes))
}

// addResponseBytes credits n response-body bytes to a byte counter, tolerating
// gin's -1 "nothing written yet" sentinel.
func addResponseBytes(counter prometheus.Counter, n int) {
	if n > 0 {
		counter.Add(float64(n))
	}
}

// MetricsHandler returns the /metrics endpoint for this server's registry. It is
// deliberately not part of Router: per-account gauges enumerate owner handles, so
// the binary exposes it only on the operator-facing AQT_METRICS_ADDR listener.
func (s *Server) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(s.metrics.registry, promhttp.HandlerOpts{})
}

// accountCollector reads per-account usage from the store on every scrape, so the
// gauges are exact at scrape time with no refresh loop to go stale. One series per
// account per gauge; the label is the opaque owner handle. The queries run on the
// read pool and touch counters, COUNT(*)s, and a SUM of the recorded blob sizes,
// which stays cheap at the account counts a self-hosted server sees. No scrape
// touches the filesystem: every row records its blob size (startup backfills the
// ones written before migration 16).
type accountCollector struct {
	store *Store
}

var (
	descAccounts = prometheus.NewDesc("aqt_accounts",
		"Number of registered accounts.", nil, nil)
	descAccountStorage = prometheus.NewDesc("aqt_account_storage_bytes",
		"Stored pack bytes per account (the quota counter).", []string{"owner"}, nil)
	descAccountObjects = prometheus.NewDesc("aqt_account_objects",
		"Stored objects per account.", []string{"owner"}, nil)
	descAccountResources = prometheus.NewDesc("aqt_account_resources",
		"Live (non-reclaimed) resources per account.", []string{"owner"}, nil)
	descAccountSnapshots = prometheus.NewDesc("aqt_account_snapshots",
		"Retained snapshots per account.", []string{"owner"}, nil)
	descAccountDevices = prometheus.NewDesc("aqt_account_devices",
		"Attached devices per account.", []string{"owner"}, nil)
)

func (a *accountCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descAccounts
	ch <- descAccountStorage
	ch <- descAccountObjects
	ch <- descAccountResources
	ch <- descAccountSnapshots
	ch <- descAccountDevices
}

func (a *accountCollector) Collect(ch chan<- prometheus.Metric) {
	usages, err := a.store.AccountUsageAll()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(descAccounts, err)
		return
	}
	ch <- prometheus.MustNewConstMetric(descAccounts, prometheus.GaugeValue, float64(len(usages)))
	for _, u := range usages {
		ch <- prometheus.MustNewConstMetric(descAccountStorage, prometheus.GaugeValue, float64(u.StorageBytes), u.Owner)
		ch <- prometheus.MustNewConstMetric(descAccountObjects, prometheus.GaugeValue, float64(u.Objects), u.Owner)
		ch <- prometheus.MustNewConstMetric(descAccountResources, prometheus.GaugeValue, float64(u.Resources), u.Owner)
		ch <- prometheus.MustNewConstMetric(descAccountSnapshots, prometheus.GaugeValue, float64(u.Snapshots), u.Owner)
		ch <- prometheus.MustNewConstMetric(descAccountDevices, prometheus.GaugeValue, float64(u.Devices), u.Owner)
	}
}
