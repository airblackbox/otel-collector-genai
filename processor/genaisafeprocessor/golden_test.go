// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: Apache-2.0

package genaisafeprocessor

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor/processortest"
)

// goldenSafeFixture represents a safety/redaction test scenario.
type goldenSafeFixture struct {
	Name        string
	Description string
	Config      Config
	Denylist    []string // denylist regex patterns
	Spans       []goldenSpanInput
	WantAttrs   map[string]string // expected span attributes (for first span)
	WantAbsent  []string          // keys that must NOT exist
	WantPresent []string          // keys that MUST exist
	WantLoop    bool              // expected genai.risk.loop_suspected flag
}

type goldenSpanInput struct {
	Name  string
	Attrs map[string]string
}

func goldenSafeFixtures() []goldenSafeFixture {
	return []goldenSafeFixture{
		{
			Name:        "redact_hash_and_preview",
			Description: "Prompt is truncated to preview_chars with hash appended",
			Config: Config{
				Redact: RedactConfig{
					Mode:         "hash_and_preview",
					PreviewChars: 15,
					Salt:         "test-salt",
					Keys:         []string{"gen_ai.prompt", "gen_ai.completion"},
				},
			},
			Spans: []goldenSpanInput{{
				Name: "llm.chat",
				Attrs: map[string]string{
					"gen_ai.prompt":     "This is a very long user prompt that contains sensitive information about the user's medical history",
					"gen_ai.completion": "Based on the information you provided about your condition, here is my recommendation...",
					"gen_ai.model":      "gpt-4o",
				},
			}},
			WantPresent: []string{"gen_ai.prompt", "gen_ai.prompt.hash", "gen_ai.completion", "gen_ai.completion.hash"},
			WantAttrs:   map[string]string{"gen_ai.model": "gpt-4o"},
		},
		{
			Name:        "redact_drop_mode",
			Description: "Drop mode removes original keys, leaves only hashes",
			Config: Config{
				Redact: RedactConfig{
					Mode:         "drop",
					PreviewChars: 10,
					Salt:         "salt",
					Keys:         []string{"gen_ai.prompt"},
				},
			},
			Spans: []goldenSpanInput{{
				Name: "llm.chat",
				Attrs: map[string]string{
					"gen_ai.prompt": "Remove this prompt entirely from traces",
					"gen_ai.model":  "gpt-4o",
				},
			}},
			WantAbsent:  []string{"gen_ai.prompt"},
			WantPresent: []string{"gen_ai.prompt.hash"},
			WantAttrs:   map[string]string{"gen_ai.model": "gpt-4o"},
		},
		{
			Name:        "redact_hash_mode",
			Description: "Hash mode replaces content with [HASHED] and adds hash",
			Config: Config{
				Redact: RedactConfig{
					Mode: "hash",
					Salt: "salt",
					Keys: []string{"gen_ai.prompt"},
				},
			},
			Spans: []goldenSpanInput{{
				Name: "llm.chat",
				Attrs: map[string]string{
					"gen_ai.prompt": "Secret prompt text",
				},
			}},
			WantAttrs:   map[string]string{"gen_ai.prompt": "[HASHED]"},
			WantPresent: []string{"gen_ai.prompt.hash"},
		},
		{
			Name:        "denylist_key_match",
			Description: "Denylist regex matches attribute keys → [REDACTED]",
			Config: Config{
				Redact: RedactConfig{
					Mode:       "hash_and_preview",
					PreviewChars: 48,
					Salt:       "salt",
					Keys:       []string{},
					DenylistRe: []string{`(?i)api[_-]?key`, `(?i)authorization`},
				},
			},
			Denylist: []string{`(?i)api[_-]?key`, `(?i)authorization`},
			Spans: []goldenSpanInput{{
				Name: "llm.chat",
				Attrs: map[string]string{
					"http.header.api_key":       "sk-secret-key-12345",
					"http.header.authorization": "Bearer sk-secret",
					"gen_ai.model":              "gpt-4o",
				},
			}},
			WantAttrs: map[string]string{
				"http.header.api_key":       "[REDACTED]",
				"http.header.authorization": "[REDACTED]",
				"gen_ai.model":              "gpt-4o",
			},
		},
		{
			Name:        "denylist_value_match",
			Description: "Denylist regex matches attribute values → [REDACTED]",
			Config: Config{
				Redact: RedactConfig{
					Mode:       "hash_and_preview",
					PreviewChars: 48,
					Salt:       "salt",
					Keys:       []string{},
					DenylistRe: []string{`(?i)sk-[a-z0-9]{20,}`},
				},
			},
			Denylist: []string{`(?i)sk-[a-z0-9]{20,}`},
			Spans: []goldenSpanInput{{
				Name: "llm.chat",
				Attrs: map[string]string{
					"some.field":   "my token is sk-abcdefghij1234567890 and it works",
					"safe.field":   "no secrets here",
				},
			}},
			WantAttrs: map[string]string{
				"some.field": "[REDACTED]",
				"safe.field": "no secrets here",
			},
		},
		{
			Name:        "loop_detection_triggered",
			Description: "Repeated tool spans trigger loop_suspected flag",
			Config: Config{
				Redact: RedactConfig{Mode: "hash_and_preview", PreviewChars: 48, Salt: "salt", Keys: []string{}},
				LoopDetection: LoopDetectionConfig{
					Enable:          true,
					ToolSpanNameRe:  `^tool\.`,
					RepeatThreshold: 3,
				},
			},
			Spans: []goldenSpanInput{
				{Name: "tool.get_weather", Attrs: map[string]string{"gen_ai.model": "gpt-4o"}},
				{Name: "tool.get_weather", Attrs: map[string]string{"gen_ai.model": "gpt-4o"}},
				{Name: "tool.get_weather", Attrs: map[string]string{"gen_ai.model": "gpt-4o"}},
				{Name: "tool.get_weather", Attrs: map[string]string{"gen_ai.model": "gpt-4o"}},
			},
			WantLoop: true,
		},
		{
			Name:        "loop_detection_not_triggered",
			Description: "Diverse tool spans do NOT trigger loop detection",
			Config: Config{
				Redact: RedactConfig{Mode: "hash_and_preview", PreviewChars: 48, Salt: "salt", Keys: []string{}},
				LoopDetection: LoopDetectionConfig{
					Enable:          true,
					ToolSpanNameRe:  `^tool\.`,
					RepeatThreshold: 3,
				},
			},
			Spans: []goldenSpanInput{
				{Name: "tool.get_weather", Attrs: map[string]string{"gen_ai.model": "gpt-4o"}},
				{Name: "tool.search_web", Attrs: map[string]string{"gen_ai.model": "gpt-4o"}},
				{Name: "tool.calculate", Attrs: map[string]string{"gen_ai.model": "gpt-4o"}},
			},
			WantLoop: false,
		},
		{
			Name:        "pii_scrubbing",
			Description: "PII patterns in denylist are redacted from all attributes",
			Config: Config{
				Redact: RedactConfig{
					Mode:       "hash_and_preview",
					PreviewChars: 48,
					Salt:       "salt",
					Keys:       []string{},
					DenylistRe: []string{
						`\b\d{3}-\d{2}-\d{4}\b`,                    // SSN
						`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, // email
					},
				},
			},
			Denylist: []string{
				`\b\d{3}-\d{2}-\d{4}\b`,
				`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
			},
			Spans: []goldenSpanInput{{
				Name: "llm.chat",
				Attrs: map[string]string{
					"gen_ai.prompt": "My SSN is 123-45-6789 and email is user@example.com",
					"gen_ai.model":  "gpt-4o",
				},
			}},
			WantAttrs: map[string]string{
				"gen_ai.prompt": "[REDACTED]",
				"gen_ai.model":  "gpt-4o",
			},
		},
		{
			Name:        "empty_span_no_crash",
			Description: "Span with no matching attributes processes without error",
			Config: Config{
				Redact: RedactConfig{
					Mode: "hash_and_preview",
					PreviewChars: 48,
					Salt: "salt",
					Keys: []string{"gen_ai.prompt"},
				},
			},
			Spans: []goldenSpanInput{{
				Name: "llm.chat",
				Attrs: map[string]string{
					"http.method": "POST",
				},
			}},
			WantAttrs: map[string]string{"http.method": "POST"},
		},
		{
			Name:        "hash_consistency_across_spans",
			Description: "Same content produces same hash (enables correlation)",
			Config: Config{
				Redact: RedactConfig{
					Mode: "hash",
					Salt: "fixed-salt",
					Keys: []string{"gen_ai.prompt"},
				},
			},
			Spans: []goldenSpanInput{
				{Name: "llm.chat.1", Attrs: map[string]string{"gen_ai.prompt": "identical content"}},
				{Name: "llm.chat.2", Attrs: map[string]string{"gen_ai.prompt": "identical content"}},
			},
			// Verified in custom test below
		},
	}
}

// TestGoldenSafe runs all safety/redaction fixtures.
func TestGoldenSafe(t *testing.T) {
	for _, fix := range goldenSafeFixtures() {
		t.Run(fix.Name, func(t *testing.T) {
			sink := new(consumertest.TracesSink)
			set := processortest.NewNopSettings()

			proc, err := newProcessor(context.Background(), set, &fix.Config, sink)
			if err != nil {
				t.Fatalf("newProcessor: %v", err)
			}

			// Compile denylists manually if specified.
			if len(fix.Denylist) > 0 {
				proc.denylist = nil
				for _, pattern := range fix.Denylist {
					re, err := regexp.Compile(pattern)
					if err != nil {
						t.Fatalf("compile denylist %q: %v", pattern, err)
					}
					proc.denylist = append(proc.denylist, re)
				}
			}

			// Compile loop detection regex.
			if fix.Config.LoopDetection.Enable && fix.Config.LoopDetection.ToolSpanNameRe != "" {
				re, err := regexp.Compile(fix.Config.LoopDetection.ToolSpanNameRe)
				if err != nil {
					t.Fatalf("compile tool regex: %v", err)
				}
				proc.toolRe = re
			}

			// Build traces with all fixture spans.
			td := ptrace.NewTraces()
			rs := td.ResourceSpans().AppendEmpty()
			ss := rs.ScopeSpans().AppendEmpty()
			for _, spanDef := range fix.Spans {
				s := ss.Spans().AppendEmpty()
				s.SetName(spanDef.Name)
				for k, v := range spanDef.Attrs {
					s.Attributes().PutStr(k, v)
				}
			}

			if err := proc.ConsumeTraces(context.Background(), td); err != nil {
				t.Fatalf("ConsumeTraces: %v", err)
			}

			if len(sink.AllTraces()) != 1 {
				t.Fatalf("expected 1 trace batch, got %d", len(sink.AllTraces()))
			}

			outSpans := sink.AllTraces()[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans()
			if outSpans.Len() == 0 {
				t.Fatal("no output spans")
			}

			firstSpan := outSpans.At(0)
			attrs := firstSpan.Attributes()

			// Check expected attributes.
			for key, want := range fix.WantAttrs {
				got, ok := attrs.Get(key)
				if !ok {
					t.Errorf("missing expected attribute %q", key)
					continue
				}
				if got.Str() != want {
					t.Errorf("%s = %q, want %q", key, got.Str(), want)
				}
			}

			// Check absent keys.
			for _, key := range fix.WantAbsent {
				if _, ok := attrs.Get(key); ok {
					t.Errorf("attribute %q should not exist", key)
				}
			}

			// Check present keys (exist but value may vary).
			for _, key := range fix.WantPresent {
				if _, ok := attrs.Get(key); !ok {
					t.Errorf("expected attribute %q to be present", key)
				}
			}

			// Check loop detection flag.
			if fix.WantLoop {
				loopVal, ok := attrs.Get("genai.risk.loop_suspected")
				if !ok {
					t.Error("expected genai.risk.loop_suspected attribute")
				} else if !loopVal.Bool() {
					t.Error("expected genai.risk.loop_suspected = true")
				}
			} else if fix.Config.LoopDetection.Enable {
				// If loop detection is on but we don't expect a loop, verify no flag
				loopVal, ok := attrs.Get("genai.risk.loop_suspected")
				if ok && loopVal.Bool() {
					t.Error("genai.risk.loop_suspected should not be true")
				}
			}
		})
	}
}

// TestGoldenSafe_HashCorrelation verifies same content → same hash across spans.
func TestGoldenSafe_HashCorrelation(t *testing.T) {
	sink := new(consumertest.TracesSink)
	set := processortest.NewNopSettings()
	cfg := &Config{
		Redact: RedactConfig{
			Mode: "hash",
			Salt: "fixed-salt",
			Keys: []string{"gen_ai.prompt"},
		},
	}

	proc, err := newProcessor(context.Background(), set, cfg, sink)
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}

	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()

	s1 := ss.Spans().AppendEmpty()
	s1.SetName("llm.chat.1")
	s1.Attributes().PutStr("gen_ai.prompt", "identical content for correlation")

	s2 := ss.Spans().AppendEmpty()
	s2.SetName("llm.chat.2")
	s2.Attributes().PutStr("gen_ai.prompt", "identical content for correlation")

	s3 := ss.Spans().AppendEmpty()
	s3.SetName("llm.chat.3")
	s3.Attributes().PutStr("gen_ai.prompt", "different content entirely")

	if err := proc.ConsumeTraces(context.Background(), td); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}

	spans := sink.AllTraces()[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans()

	h1, _ := spans.At(0).Attributes().Get("gen_ai.prompt.hash")
	h2, _ := spans.At(1).Attributes().Get("gen_ai.prompt.hash")
	h3, _ := spans.At(2).Attributes().Get("gen_ai.prompt.hash")

	if h1.Str() != h2.Str() {
		t.Error("identical content should produce identical hashes")
	}
	if h1.Str() == h3.Str() {
		t.Error("different content should produce different hashes")
	}
}

// TestGoldenSafe_EmptyTraces verifies processor handles empty trace batches.
func TestGoldenSafe_EmptyTraces(t *testing.T) {
	sink := new(consumertest.TracesSink)
	set := processortest.NewNopSettings()
	cfg := &Config{
		Redact: RedactConfig{Mode: "hash", Salt: "salt", Keys: []string{"gen_ai.prompt"}},
	}

	proc, err := newProcessor(context.Background(), set, cfg, sink)
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}

	td := ptrace.NewTraces()
	if err := proc.ConsumeTraces(context.Background(), td); err != nil {
		t.Fatalf("empty ConsumeTraces should not fail: %v", err)
	}
}

// TestGoldenSafe_NoPlaintextLeak is a security test that verifies no prompt/completion
// content survives in the span after redaction in any mode.
func TestGoldenSafe_NoPlaintextLeak(t *testing.T) {
	modes := []string{"drop", "hash", "hash_and_preview", "truncate"}
	sensitiveContent := "My social security number is 123-45-6789 and my password is hunter2"

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			sink := new(consumertest.TracesSink)
			set := processortest.NewNopSettings()
			cfg := &Config{
				Redact: RedactConfig{
					Mode:         mode,
					PreviewChars: 10,
					Salt:         "salt",
					Keys:         []string{"gen_ai.prompt"},
				},
			}

			proc, _ := newProcessor(context.Background(), set, cfg, sink)

			td := ptrace.NewTraces()
			rs := td.ResourceSpans().AppendEmpty()
			ss := rs.ScopeSpans().AppendEmpty()
			s := ss.Spans().AppendEmpty()
			s.SetName("llm.chat")
			s.Attributes().PutStr("gen_ai.prompt", sensitiveContent)

			proc.ConsumeTraces(context.Background(), td)

			// Check all string attributes for the full sensitive content.
			span := sink.AllTraces()[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
			span.Attributes().Range(func(k string, v pcommon.Value) bool {
				if v.Type() == pcommon.ValueTypeStr {
					if strings.Contains(v.Str(), sensitiveContent) {
						t.Errorf("mode=%s: attribute %q still contains full sensitive content", mode, k)
					}
					// Also check for known PII fragments
					if strings.Contains(v.Str(), "123-45-6789") {
						t.Errorf("mode=%s: attribute %q leaks SSN", mode, k)
					}
					if strings.Contains(v.Str(), "hunter2") {
						t.Errorf("mode=%s: attribute %q leaks password", mode, k)
					}
				}
				return true
			})
		})
	}
}
