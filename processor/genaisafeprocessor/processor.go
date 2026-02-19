package genaisafeprocessor

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

type genaiSafeProcessor struct {
	logger       *zap.Logger
	config       *Config
	redactor     *Redactor
	loopDetector *LoopDetector
	nextConsumer consumer.Traces
	keysSet      map[string]bool
}

func newGenaiSafeProcessor(
	logger *zap.Logger,
	cfg *Config,
	redactor *Redactor,
	detector *LoopDetector,
	next consumer.Traces,
) *genaiSafeProcessor {
	keysSet := make(map[string]bool, len(cfg.Redact.Keys))
	for _, k := range cfg.Redact.Keys {
		keysSet[k] = true
	}

	return &genaiSafeProcessor{
		logger:       logger,
		config:       cfg,
		redactor:     redactor,
		loopDetector: detector,
		nextConsumer: next,
		keysSet:      keysSet,
	}
}

func (p *genaiSafeProcessor) Start(_ context.Context, _ component.Host) error {
	p.logger.Info("genaisafe processor started",
		zap.Bool("redaction", true),
		zap.Bool("metrics", p.config.Metrics.Enable),
		zap.Bool("loop_detection", p.config.LoopDetection.Enable),
	)
	return nil
}

func (p *genaiSafeProcessor) Shutdown(_ context.Context) error {
	return nil
}

func (p *genaiSafeProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (p *genaiSafeProcessor) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		ilss := rss.At(i).ScopeSpans()
		for j := 0; j < ilss.Len(); j++ {
			spans := ilss.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				p.processSpan(spans.At(k))
			}
		}
	}
	return p.nextConsumer.ConsumeTraces(ctx, td)
}

func (p *genaiSafeProcessor) processSpan(span ptrace.Span) {
	attrs := span.Attributes()

	// Step 1: Redact sensitive attribute values
	p.redactAttributes(attrs)

	// Step 2: Loop detection
	if p.loopDetector != nil {
		p.detectLoops(span, attrs)
	}

	// Step 3: Token metrics (add summary attributes)
	if p.config.Metrics.Enable {
		p.addMetrics(attrs)
	}
}

func (p *genaiSafeProcessor) redactAttributes(attrs pcommon.Map) {
	type redaction struct {
		key   string
		value string
	}
	var toRedact []redaction

	attrs.Range(func(key string, val pcommon.Value) bool {
		strVal := val.Str()
		if strVal == "" {
			return true
		}

		// Redact if key is in the redaction set
		if p.keysSet[key] {
			toRedact = append(toRedact, redaction{key: key, value: strVal})
			return true
		}

		// Redact if value matches denylist patterns
		if p.redactor.ContainsSensitive(strVal) {
			toRedact = append(toRedact, redaction{key: key, value: strVal})
		}
		return true
	})

	for _, r := range toRedact {
		attrs.PutStr(r.key, p.redactor.Redact(r.value))
	}
}

func (p *genaiSafeProcessor) detectLoops(span ptrace.Span, attrs pcommon.Map) {
	prompt, exists := attrs.Get("gen_ai.prompt")
	if !exists {
		return
	}

	traceID := span.TraceID().String()
	loopDetected, count := p.loopDetector.Check(traceID, prompt.Str())

	if loopDetected {
		attrs.PutBool("gen_ai.loop_detected", true)
		attrs.PutInt("gen_ai.loop_count", int64(count))
		p.logger.Warn("potential infinite loop detected",
			zap.String("trace_id", traceID),
			zap.Int("repeat_count", count),
		)
	}
}

func (p *genaiSafeProcessor) addMetrics(attrs pcommon.Map) {
	// Calculate total tokens if individual counts are present
	inputTokens, hasInput := attrs.Get("gen_ai.usage.input_tokens")
	outputTokens, hasOutput := attrs.Get("gen_ai.usage.output_tokens")

	if hasInput && hasOutput {
		total := inputTokens.Int() + outputTokens.Int()
		if _, exists := attrs.Get("gen_ai.usage.total_tokens"); !exists {
			attrs.PutInt("gen_ai.usage.total_tokens", total)
		}
	}

	// Add processor marker
	attrs.PutBool("gen_ai.safe.processed", true)
}