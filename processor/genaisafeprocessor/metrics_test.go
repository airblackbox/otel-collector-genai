// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: Apache-2.0

package genaisafeprocessor

import (
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

func TestMetricsEmitter_ObserveSpan_Tokens(t *testing.T) {
	logger := zap.NewNop()
	cfg := MetricsConfig{
		Enable:       true,
		EmitInterval: 10 * time.Second,
		TokenAttrCandidates: []string{
			"gen_ai.usage.prompt_tokens",
			"gen_ai.usage.completion_tokens",
		},
		CostAttrCandidates: []string{"gen_ai.usage.cost_usd"},
	}
	m := newMetricsEmitter(logger, cfg)

	// Create a span with token attributes
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	s := ss.Spans().AppendEmpty()
	s.SetName("llm.chat")
	s.Attributes().PutInt("gen_ai.usage.prompt_tokens", 150)
	s.Attributes().PutInt("gen_ai.usage.completion_tokens", 89)

	m.observeSpan(s)

	// Check normalized attributes were added
	val, ok := s.Attributes().Get("genai.tokens.prompt")
	if !ok || val.Int() != 150 {
		t.Errorf("expected genai.tokens.prompt=150, got %v", val)
	}

	val, ok = s.Attributes().Get("genai.tokens.completion")
	if !ok || val.Int() != 89 {
		t.Errorf("expected genai.tokens.completion=89, got %v", val)
	}

	val, ok = s.Attributes().Get("genai.tokens.total")
	if !ok || val.Int() != 239 {
		t.Errorf("expected genai.tokens.total=239, got %v", val)
	}

	// Check internal counters
	if m.sumPromptTokens != 150 {
		t.Errorf("expected sumPromptTokens=150, got %d", m.sumPromptTokens)
	}
	if m.sumCompletionTokens != 89 {
		t.Errorf("expected sumCompletionTokens=89, got %d", m.sumCompletionTokens)
	}
	if m.totalSpans != 1 {
		t.Errorf("expected totalSpans=1, got %d", m.totalSpans)
	}
}

func TestMetricsEmitter_ObserveSpan_Cost(t *testing.T) {
	logger := zap.NewNop()
	cfg := MetricsConfig{
		Enable:              true,
		EmitInterval:        10 * time.Second,
		TokenAttrCandidates: []string{},
		CostAttrCandidates:  []string{"gen_ai.usage.cost_usd"},
	}
	m := newMetricsEmitter(logger, cfg)

	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	s := ss.Spans().AppendEmpty()
	s.SetName("llm.chat")
	s.Attributes().PutDouble("gen_ai.usage.cost_usd", 0.0035)

	m.observeSpan(s)

	val, ok := s.Attributes().Get("genai.cost.usd")
	if !ok {
		t.Fatal("expected genai.cost.usd attribute")
	}
	if val.Double() < 0.003 || val.Double() > 0.004 {
		t.Errorf("expected cost ~0.0035, got %f", val.Double())
	}

	if m.sumCostMicros != 3500 {
		t.Errorf("expected sumCostMicros=3500, got %d", m.sumCostMicros)
	}
}

func TestMetricsEmitter_NoTokens(t *testing.T) {
	logger := zap.NewNop()
	cfg := MetricsConfig{
		Enable:              true,
		EmitInterval:        10 * time.Second,
		TokenAttrCandidates: []string{"gen_ai.usage.prompt_tokens"},
		CostAttrCandidates:  []string{},
	}
	m := newMetricsEmitter(logger, cfg)

	// Span without any token attributes
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	s := ss.Spans().AppendEmpty()
	s.SetName("http.request")

	m.observeSpan(s)

	// Should not add normalized attrs if source attrs don't exist
	_, ok := s.Attributes().Get("genai.tokens.prompt")
	if ok {
		t.Error("should not add genai.tokens.prompt when source attr missing")
	}

	if m.sumPromptTokens != 0 {
		t.Errorf("expected sumPromptTokens=0, got %d", m.sumPromptTokens)
	}
}

func TestContainsCI(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"gen_ai.usage.prompt_tokens", "prompt", true},
		{"gen_ai.usage.COMPLETION_tokens", "completion", true},
		{"gen_ai.usage.prompt_tokens", "completion", false},
		{"", "test", false},
		{"test", "", true},
	}
	for _, tt := range tests {
		got := containsCI(tt.s, tt.sub)
		if got != tt.want {
			t.Errorf("containsCI(%q, %q) = %v, want %v", tt.s, tt.sub, got, tt.want)
		}
	}
}
