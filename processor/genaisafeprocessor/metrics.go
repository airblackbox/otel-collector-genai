// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: Apache-2.0

package genaisafeprocessor

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// metricsEmitter extracts token/cost data from spans and logs
// periodic summaries. MVP approach — week 2 will emit real
// OTel metrics via a trace-to-metrics connector.
type metricsEmitter struct {
	mu       sync.Mutex
	logger   *zap.Logger
	cfg      MetricsConfig
	lastEmit time.Time

	// Aggregated counters
	totalSpans          int64
	sumPromptTokens     int64
	sumCompletionTokens int64
	sumCostMicros       int64 // USD * 1_000_000
}

func newMetricsEmitter(logger *zap.Logger, cfg MetricsConfig) *metricsEmitter {
	return &metricsEmitter{
		logger:   logger,
		cfg:      cfg,
		lastEmit: time.Now(),
	}
}

// observeSpan extracts token counts and cost from a span,
// normalizes attribute names, and accumulates totals.
func (m *metricsEmitter) observeSpan(s ptrace.Span) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalSpans++
	attrs := s.Attributes()

	p := findIntAttr(attrs, m.cfg.TokenAttrCandidates, "prompt")
	c := findIntAttr(attrs, m.cfg.TokenAttrCandidates, "completion")

	if p > 0 {
		m.sumPromptTokens += p
		attrs.PutInt("genai.tokens.prompt", p)
	}
	if c > 0 {
		m.sumCompletionTokens += c
		attrs.PutInt("genai.tokens.completion", c)
		attrs.PutInt("genai.tokens.total", p+c)
	}

	cost := findFloatAttr(attrs, m.cfg.CostAttrCandidates)
	if cost > 0 {
		m.sumCostMicros += int64(cost * 1_000_000.0)
		attrs.PutDouble("genai.cost.usd", cost)
	}
}

// maybeEmit logs a metric summary if the emit interval has elapsed.
func (m *metricsEmitter) maybeEmit(_ context.Context, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if now.Sub(m.lastEmit) < m.cfg.EmitInterval {
		return
	}
	m.lastEmit = now
	m.logger.Info("genaisafe metric summary",
		zap.Int64("spans_processed", m.totalSpans),
		zap.Int64("prompt_tokens", m.sumPromptTokens),
		zap.Int64("completion_tokens", m.sumCompletionTokens),
		zap.Float64("cost_usd", float64(m.sumCostMicros)/1_000_000.0),
	)
}

// --- helpers ---

func findIntAttr(attrs pcommon.Map, keys []string, kind string) int64 {
	for _, k := range keys {
		if kind != "" && !containsCI(k, kind) {
			continue
		}
		v, ok := attrs.Get(k)
		if !ok {
			continue
		}
		switch v.Type() {
		case pcommon.ValueTypeInt:
			return v.Int()
		case pcommon.ValueTypeDouble:
			return int64(v.Double())
		case pcommon.ValueTypeStr:
			if n, err := strconv.ParseInt(v.Str(), 10, 64); err == nil {
				return n
			}
		}
	}
	return 0
}

func findFloatAttr(attrs pcommon.Map, keys []string) float64 {
	for _, k := range keys {
		v, ok := attrs.Get(k)
		if !ok {
			continue
		}
		switch v.Type() {
		case pcommon.ValueTypeDouble:
			return v.Double()
		case pcommon.ValueTypeInt:
			return float64(v.Int())
		case pcommon.ValueTypeStr:
			if n, err := strconv.ParseFloat(v.Str(), 64); err == nil {
				return n
			}
		}
	}
	return 0
}

func containsCI(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
