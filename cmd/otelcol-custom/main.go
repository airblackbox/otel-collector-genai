// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: Apache-2.0

// Custom OTel Collector binary with the genaisafe processor.
package main

import (
	"log"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/provider/envprovider"
	"go.opentelemetry.io/collector/confmap/provider/fileprovider"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"

	"github.com/nostalgicskinco/opentelemetry-collector-processor-genai/processor/genaisafeprocessor"
)

func main() {
	info := component.BuildInfo{
		Command:     "otelcol-genai-safe",
		Description: "OTel Collector with GenAI safety processor",
		Version:     "0.1.0",
	}

	set := otelcol.CollectorSettings{
		BuildInfo: info,
		Factories: factories,
		ConfigProviderSettings: otelcol.ConfigProviderSettings{
			ResolverSettings: confmap.ResolverSettings{
				URIs: []string{"file:./examples/otelcol-config.yaml"},
				ProviderFactories: []confmap.ProviderFactory{
					fileprovider.NewFactory(),
					envprovider.NewFactory(),
				},
			},
		},
		LoggingOptions: []zap.Option{},
	}

	cmd := otelcol.NewCommand(set)
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func factories() (otelcol.Factories, error) {
	procs, err := processor.MakeFactoryMap(
		genaisafeprocessor.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, err
	}

	return otelcol.Factories{
		Processors: procs,
	}, nil
}
