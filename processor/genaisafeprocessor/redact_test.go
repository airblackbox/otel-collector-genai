// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: Apache-2.0

package genaisafeprocessor

import (
	"regexp"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

func newTestSpan(attrs map[string]string) ptrace.Span {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	s := ss.Spans().AppendEmpty()
	s.SetName("test-span")
	for k, v := range attrs {
		s.Attributes().PutStr(k, v)
	}
	return s
}

func TestRedactSpan_HashAndPreview(t *testing.T) {
	cfg := &Config{
		Redact: RedactConfig{
			Mode:         "hash_and_preview",
			PreviewChars: 10,
			Salt:         "test-salt",
			Keys:         []string{"gen_ai.prompt"},
			DenylistRe:   []string{},
		},
	}

	p := &genAIProc{cfg: cfg, denylist: nil}
	span := newTestSpan(map[string]string{
		"gen_ai.prompt": "This is a very long prompt that should be truncated",
	})

	p.redactSpan(span)

	// Check truncation happened
	val, ok := span.Attributes().Get("gen_ai.prompt")
	if !ok {
		t.Fatal("gen_ai.prompt attribute missing after redaction")
	}
	if len(val.Str()) > 15 { // 10 chars + "…"
		t.Errorf("expected truncated value, got: %q", val.Str())
	}

	// Check hash was added
	hashVal, ok := span.Attributes().Get("gen_ai.prompt.hash")
	if !ok {
		t.Fatal("gen_ai.prompt.hash attribute missing after redaction")
	}
	if len(hashVal.Str()) != 64 { // SHA256 hex
		t.Errorf("expected 64-char SHA256 hash, got length %d", len(hashVal.Str()))
	}
}

func TestRedactSpan_Drop(t *testing.T) {
	cfg := &Config{
		Redact: RedactConfig{
			Mode:         "drop",
			PreviewChars: 10,
			Salt:         "test-salt",
			Keys:         []string{"gen_ai.prompt"},
			DenylistRe:   []string{},
		},
	}

	p := &genAIProc{cfg: cfg, denylist: nil}
	span := newTestSpan(map[string]string{
		"gen_ai.prompt": "Secret prompt text",
	})

	p.redactSpan(span)

	// Original key should be removed
	_, ok := span.Attributes().Get("gen_ai.prompt")
	if ok {
		t.Error("gen_ai.prompt should have been dropped")
	}

	// Hash should exist
	_, ok = span.Attributes().Get("gen_ai.prompt.hash")
	if !ok {
		t.Error("gen_ai.prompt.hash should exist after drop")
	}
}

func TestRedactSpan_Denylist(t *testing.T) {
	cfg := &Config{
		Redact: RedactConfig{
			Mode:       "hash_and_preview",
			PreviewChars: 48,
			Salt:       "test",
			Keys:       []string{},
			DenylistRe: []string{`(?i)api[_-]?key`, `(?i)sk-[a-z0-9]{20,}`},
		},
	}

	var denylist []*regexp.Regexp
	for _, s := range cfg.Redact.DenylistRe {
		re, _ := regexp.Compile(s)
		denylist = append(denylist, re)
	}

	p := &genAIProc{cfg: cfg, denylist: denylist}
	span := newTestSpan(map[string]string{
		"http.header.api_key": "sk-abc123",
		"safe.attribute":      "normal value",
	})

	p.redactSpan(span)

	// api_key attr should be redacted
	val, _ := span.Attributes().Get("http.header.api_key")
	if val.Str() != "[REDACTED]" {
		t.Errorf("expected [REDACTED], got: %q", val.Str())
	}

	// Safe attribute should be untouched
	val, _ = span.Attributes().Get("safe.attribute")
	if val.Str() != "normal value" {
		t.Errorf("safe attribute was modified: %q", val.Str())
	}
}

func TestRedactSpan_DenylistMatchesValue(t *testing.T) {
	cfg := &Config{
		Redact: RedactConfig{
			Mode:       "hash_and_preview",
			PreviewChars: 48,
			Salt:       "test",
			Keys:       []string{},
			DenylistRe: []string{`(?i)sk-[a-z0-9]{20,}`},
		},
	}

	re, _ := regexp.Compile(`(?i)sk-[a-z0-9]{20,}`)
	p := &genAIProc{cfg: cfg, denylist: []*regexp.Regexp{re}}
	span := newTestSpan(map[string]string{
		"some.field": "token is sk-abcdefghij1234567890",
	})

	p.redactSpan(span)

	val, _ := span.Attributes().Get("some.field")
	if val.Str() != "[REDACTED]" {
		t.Errorf("expected value containing sk- key to be redacted, got: %q", val.Str())
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		n        int
		expected string
	}{
		{"short", 10, "short"},
		{"a longer string", 5, "a lon…"},
		{"", 5, ""},
		{"hello", 0, "hello"},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.n)
		if got != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.expected)
		}
	}
}

func TestRedactSpan_HashConsistency(t *testing.T) {
	cfg := &Config{
		Redact: RedactConfig{
			Mode:         "hash",
			PreviewChars: 48,
			Salt:         "fixed-salt",
			Keys:         []string{"gen_ai.prompt"},
		},
	}

	p := &genAIProc{cfg: cfg}

	// Two spans with the same prompt should get the same hash
	span1 := newTestSpan(map[string]string{"gen_ai.prompt": "Hello world"})
	span2 := newTestSpan(map[string]string{"gen_ai.prompt": "Hello world"})

	p.redactSpan(span1)
	p.redactSpan(span2)

	h1, _ := span1.Attributes().Get("gen_ai.prompt.hash")
	h2, _ := span2.Attributes().Get("gen_ai.prompt.hash")

	if h1.Str() != h2.Str() {
		t.Error("same input should produce same hash for correlation")
	}

	// Different prompt should produce different hash
	span3 := newTestSpan(map[string]string{"gen_ai.prompt": "Different prompt"})
	p.redactSpan(span3)
	h3, _ := span3.Attributes().Get("gen_ai.prompt.hash")

	if h1.Str() == h3.Str() {
		t.Error("different inputs should produce different hashes")
	}

	// Value should be [HASHED] in hash mode
	v1, _ := span1.Attributes().Get("gen_ai.prompt")
	if !strings.Contains(v1.Str(), "[HASHED]") {
		t.Errorf("expected [HASHED], got: %q", v1.Str())
	}
}
