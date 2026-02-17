package genaisafeprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

func newTestProcessor(t *testing.T) (*genaiSafeProcessor, *consumertest.TracesSink) {
	t.Helper()
	cfg := createDefaultConfig()
	redactor, err := NewRedactor(cfg.Redact)
	if err != nil {
		t.Fatalf("failed to create redactor: %v", err)
	}
	detector := NewLoopDetector(cfg.LoopDetection.RepeatThreshold)
	sink := new(consumertest.TracesSink)
	proc := newGenaiSafeProcessor(zap.NewNop(), cfg, redactor, detector, sink)
	return proc, sink
}

func TestRedactPromptContent(t *testing.T) {
	proc, sink := newTestProcessor(t)

	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("chat")
	span.Attributes().PutStr("gen_ai.prompt", "Tell me about quantum computing in detail")
	span.Attributes().PutStr("gen_ai.completion", "Quantum computing uses qubits instead of bits")

	err := proc.ConsumeTraces(context.Background(), td)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attrs := sink.AllTraces()[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()

	prompt, _ := attrs.Get("gen_ai.prompt")
	if !strings.Contains(prompt.Str(), "[sha256:") {
		t.Errorf("expected redacted prompt with hash, got: %s", prompt.Str())
	}

	completion, _ := attrs.Get("gen_ai.completion")
	if !strings.Contains(completion.Str(), "[sha256:") {
		t.Errorf("expected redacted completion with hash, got: %s", completion.Str())
	}
}

func TestRedactAPIKey(t *testing.T) {
	proc, sink := newTestProcessor(t)

	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.Attributes().PutStr("some_field", "my api_key is sk-abc123def456ghi789jkl012mno345pqr")

	proc.ConsumeTraces(context.Background(), td)

	attrs := sink.AllTraces()[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()

	val, _ := attrs.Get("some_field")
	if strings.Contains(val.Str(), "sk-abc123") {
		t.Errorf("expected API key to be redacted, got: %s", val.Str())
	}
}

func TestLoopDetection(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.LoopDetection.RepeatThreshold = 3
	redactor, _ := NewRedactor(cfg.Redact)
	detector := NewLoopDetector(3)
	sink := new(consumertest.TracesSink)
	proc := newGenaiSafeProcessor(zap.NewNop(), cfg, redactor, detector, sink)

	traceID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// Send the same prompt 3 times
	for i := 0; i < 3; i++ {
		td := ptrace.NewTraces()
		span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
		span.SetTraceID(traceID)
		span.Attributes().PutStr("gen_ai.prompt", "repeat this exact prompt")

		proc.ConsumeTraces(context.Background(), td)
	}

	// The 3rd trace should have loop detected
	traces := sink.AllTraces()
	lastAttrs := traces[2].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()

	loopDetected, ok := lastAttrs.Get("gen_ai.loop_detected")
	if !ok || !loopDetected.Bool() {
		t.Error("expected loop to be detected after 3 repeats")
	}

	loopCount, ok := lastAttrs.Get("gen_ai.loop_count")
	if !ok || loopCount.Int() < 3 {
		t.Errorf("expected loop_count >= 3, got %v", loopCount)
	}
}

func TestTokenMetrics(t *testing.T) {
	proc, sink := newTestProcessor(t)

	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.Attributes().PutInt("gen_ai.usage.input_tokens", 100)
	span.Attributes().PutInt("gen_ai.usage.output_tokens", 50)

	proc.ConsumeTraces(context.Background(), td)

	attrs := sink.AllTraces()[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()

	total, ok := attrs.Get("gen_ai.usage.total_tokens")
	if !ok || total.Int() != 150 {
		t.Errorf("expected total_tokens=150, got %v", total)
	}

	processed, ok := attrs.Get("gen_ai.safe.processed")
	if !ok || !processed.Bool() {
		t.Error("expected gen_ai.safe.processed=true")
	}
}

func TestHashAndPreviewMode(t *testing.T) {
	cfg := RedactConfig{
		Mode:         "hash_and_preview",
		PreviewChars: 10,
		Salt:         "test-salt",
		DenylistRegex: []string{},
	}
	redactor, _ := NewRedactor(cfg)

	result := redactor.Redact("This is a longer string that should be previewed")

	if !strings.HasPrefix(result, "This is a ") {
		t.Errorf("expected preview prefix, got: %s", result)
	}
	if !strings.Contains(result, "[sha256:") {
		t.Errorf("expected sha256 hash, got: %s", result)
	}
}

func TestFullHashMode(t *testing.T) {
	cfg := RedactConfig{
		Mode:         "full_hash",
		Salt:         "test-salt",
		DenylistRegex: []string{},
	}
	redactor, _ := NewRedactor(cfg)

	result := redactor.Redact("sensitive content")

	if !strings.HasPrefix(result, "[sha256:") {
		t.Errorf("expected full hash, got: %s", result)
	}
	if strings.Contains(result, "sensitive") {
		t.Error("full hash mode should not contain original content")
	}
}

func TestLoopDetectorClear(t *testing.T) {
	detector := NewLoopDetector(3)

	detector.Check("trace-1", "prompt A")
	detector.Check("trace-1", "prompt A")

	if detector.ActiveTraces() != 1 {
		t.Errorf("expected 1 active trace, got %d", detector.ActiveTraces())
	}

	detector.Clear("trace-1")

	if detector.ActiveTraces() != 0 {
		t.Errorf("expected 0 active traces after clear, got %d", detector.ActiveTraces())
	}
}