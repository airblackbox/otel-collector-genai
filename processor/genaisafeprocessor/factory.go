package genaisafeprocessor

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
)

const (
	typeStr   = "genaisafe"
	stability = component.StabilityLevelAlpha
)

// NewFactory creates a factory for the genaisafe processor.
func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(typeStr),
		func() component.Config { return createDefaultConfig() },
		processor.WithTraces(createTracesProcessor, stability),
	)
}

func createTracesProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	nextConsumer consumer.Traces,
) (processor.Traces, error) {
	pCfg := cfg.(*Config)

	redactor, err := NewRedactor(pCfg.Redact)
	if err != nil {
		return nil, fmt.Errorf("create redactor: %w", err)
	}

	var detector *LoopDetector
	if pCfg.LoopDetection.Enable {
		detector = NewLoopDetector(pCfg.LoopDetection.RepeatThreshold)
	}

	return newGenaiSafeProcessor(set.Logger, pCfg, redactor, detector, nextConsumer), nil
}