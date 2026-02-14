// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: Apache-2.0

package genaisafeprocessor

import (
	"regexp"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

func makeSpanSlice(names []string) ptrace.SpanSlice {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	spans := ss.Spans()
	for _, name := range names {
		s := spans.AppendEmpty()
		s.SetName(name)
	}
	return spans
}

func TestDetectSimpleLoop_Triggered(t *testing.T) {
	toolRe := regexp.MustCompile(`(?i)tool|function|call`)
	spans := makeSpanSlice([]string{
		"call_search_tool",
		"call_search_tool",
		"call_search_tool",
		"call_search_tool",
		"call_search_tool",
		"call_search_tool", // 6th repeat
	})

	if !detectSimpleLoop(spans, toolRe, 6) {
		t.Error("expected loop detection to trigger at 6 repeats")
	}
}

func TestDetectSimpleLoop_NotTriggered(t *testing.T) {
	toolRe := regexp.MustCompile(`(?i)tool|function|call`)
	spans := makeSpanSlice([]string{
		"call_search_tool",
		"call_weather_tool",
		"call_search_tool",
		"call_calendar_tool",
		"process_result",
	})

	if detectSimpleLoop(spans, toolRe, 6) {
		t.Error("loop detection should NOT trigger with varied tool names")
	}
}

func TestDetectSimpleLoop_IgnoresNonToolSpans(t *testing.T) {
	toolRe := regexp.MustCompile(`(?i)tool|function|call`)
	spans := makeSpanSlice([]string{
		"http.request",
		"http.request",
		"http.request",
		"http.request",
		"http.request",
		"http.request",
		"http.request",
		"http.request",
	})

	if detectSimpleLoop(spans, toolRe, 6) {
		t.Error("non-tool spans should not trigger loop detection")
	}
}

func TestDetectSimpleLoop_ThresholdEdge(t *testing.T) {
	toolRe := regexp.MustCompile(`(?i)tool|function|call`)

	// 5 repeats should NOT trigger with threshold 6
	spans5 := makeSpanSlice([]string{
		"call_tool", "call_tool", "call_tool",
		"call_tool", "call_tool",
	})
	if detectSimpleLoop(spans5, toolRe, 6) {
		t.Error("5 repeats should not trigger threshold of 6")
	}

	// 6 repeats SHOULD trigger
	spans6 := makeSpanSlice([]string{
		"call_tool", "call_tool", "call_tool",
		"call_tool", "call_tool", "call_tool",
	})
	if !detectSimpleLoop(spans6, toolRe, 6) {
		t.Error("6 repeats should trigger threshold of 6")
	}
}

func TestDetectSimpleLoop_DefaultThreshold(t *testing.T) {
	toolRe := regexp.MustCompile(`(?i)tool|function|call`)
	spans := makeSpanSlice([]string{
		"call_tool", "call_tool", "call_tool",
		"call_tool", "call_tool", "call_tool",
	})

	// threshold=0 should default to 6
	if !detectSimpleLoop(spans, toolRe, 0) {
		t.Error("zero threshold should default to 6 and trigger")
	}
}
