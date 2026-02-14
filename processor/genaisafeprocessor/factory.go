// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: Apache-2.0

package genaisafeprocessor

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
)

const (
	typeStr   = "genaisafe"
	stability = component.StabilityLevelBeta
)

// NewFactory returns a processor.Factory for genaisafe.
func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		processor.WithTraces(createTracesProcessor, stability),
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		Redact: RedactConfig{
			Mode:         "hash_and_preview",
			PreviewChars: 48,
			Salt:         "change-me",
			Keys: []string{
				"gen_ai.prompt",
				"gen_ai.completion",
				"llm.prompt",
				"llm.completion",
				"genai.prompt",
				"genai.completion",
			},
			DenylistRe: []string{
				`(?i)api[_-]?key`,
				`(?i)authorization`,
				`(?i)bearer\s+[a-z0-9\-\._~\+\/]+=*`,
				`(?i)sk-[a-z0-9]{20,}`,
			},
		},
		Metrics: MetricsConfig{
			Enable:       true,
			EmitInterval: 10_000_000_000, // 10s
			TokenAttrCandidates: []string{
				"gen_ai.usage.prompt_tokens",
				"gen_ai.usage.completion_tokens",
				"llm.usage.prompt_tokens",
				"llm.usage.completion_tokens",
			},
			CostAttrCandidates: []string{
				"gen_ai.usage.cost_usd",
				"llm.usage.cost_usd",
			},
		},
		LoopDetection: LoopDetectionConfig{
			Enable:          true,
			ToolSpanNameRe:  `(?i)tool|function|call`,
			RepeatThreshold: 6,
		},
	}
}

func createTracesProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	next consumer.Traces,
) (processor.Traces, error) {
	c := cfg.(*Config)
	return newProcessor(ctx, set, c, next)
}
