// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: Apache-2.0

package genaisafeprocessor

import (
	"context"
	"regexp"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"
)

type genAIProc struct {
	logger   *zap.Logger
	cfg      *Config
	next     consumer.Traces
	denylist []*regexp.Regexp
	toolRe   *regexp.Regexp
	metrics  *metricsEmitter
}

func newProcessor(
	_ context.Context,
	set processor.Settings,
	cfg *Config,
	next consumer.Traces,
) (*genAIProc, error) {
	p := &genAIProc{
		logger: set.Logger,
		cfg:    cfg,
		next:   next,
	}

	// Compile denylist regexes
	for _, s := range cfg.Redact.DenylistRe {
		re, err := regexp.Compile(s)
		if err != nil {
			set.Logger.Warn("invalid denylist regex, skipping",
				zap.String("regex", s), zap.Error(err))
			continue
		}
		p.denylist = append(p.denylist, re)
	}

	// Compile tool-span regex for loop detection
	if cfg.LoopDetection.Enable && cfg.LoopDetection.ToolSpanNameRe != "" {
		re, err := regexp.Compile(cfg.LoopDetection.ToolSpanNameRe)
		if err != nil {
			set.Logger.Warn("invalid tool span regex",
				zap.String("regex", cfg.LoopDetection.ToolSpanNameRe),
				zap.Error(err))
		} else {
			p.toolRe = re
		}
	}

	// Initialize metrics emitter
	if cfg.Metrics.Enable {
		p.metrics = newMetricsEmitter(set.Logger, cfg.Metrics)
	}

	return p, nil
}

func (p *genAIProc) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (p *genAIProc) Start(_ context.Context, _ component.Host) error {
	p.logger.Info("genaisafe processor started")
	return nil
}

func (p *genAIProc) Shutdown(_ context.Context) error {
	p.logger.Info("genaisafe processor stopped")
	return nil
}

func (p *genAIProc) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	rs := td.ResourceSpans()
	for i := 0; i < rs.Len(); i++ {
		scopeSpans := rs.At(i).ScopeSpans()
		for j := 0; j < scopeSpans.Len(); j++ {
			spans := scopeSpans.At(j).Spans()

			var loopFlag bool
			if p.cfg.LoopDetection.Enable && p.toolRe != nil {
				loopFlag = detectSimpleLoop(
					spans, p.toolRe, p.cfg.LoopDetection.RepeatThreshold,
				)
			}

			for k := 0; k < spans.Len(); k++ {
				s := spans.At(k)
				p.redactSpan(s)

				if loopFlag {
					s.Attributes().PutBool("genai.risk.loop_suspected", true)
				}
				if p.metrics != nil {
					p.metrics.observeSpan(s)
				}
			}
		}
	}

	if p.metrics != nil {
		p.metrics.maybeEmit(ctx, time.Now())
	}

	return p.next.ConsumeTraces(ctx, td)
}
