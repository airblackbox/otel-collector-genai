// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: Apache-2.0

// Custom OTel Collector binary with the genaisafe processor.
package main

import (
	"fmt"
	"log"
	"os"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/provider/envprovider"
	"go.opentelemetry.io/collector/confmap/provider/fileprovider"
	"go.opentelemetry.io/collector/otelcol"

	// Import our custom processor
	"github.com/nostalgicskinco/opentelemetry-collector-processor-genai/processor/genaisafeprocessor"
)

func main() {
	info := component.BuildInfo{
		Command:     "otelcol-genai-safe",
		Description: "OTel Collector with GenAI safety processor",
		Version:     "0.1.0",
	}

	factories, err := components()
	if err != nil {
		log.Fatalf("failed to build components: %v", err)
	}

	set := otelcol.CollectorSettings{
		BuildInfo: info,
		Factories: factories,
		ConfigProviderSettings: otelcol.ConfigProviderSettings{
			ResolverSettings: confmap.ResolverSettings{
				URIs: []string{configFlag()},
				ProviderFactories: []confmap.ProviderFactory{
					fileprovider.NewFactory(),
					envprovider.NewFactory(),
				},
			},
		},
	}

	if err := run(set); err != nil {
		log.Fatal(err)
	}
}

func components() (otelcol.Factories, error) {
	var err error
	factories := otelcol.Factories{}

	// Register the genaisafe processor
	factories.Processors, err = processor.MakeFactoryMap(
		genaisafeprocessor.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, fmt.Errorf("processors: %w", err)
	}

	return factories, nil
}

func run(set otelcol.CollectorSettings) error {
	cmd := otelcol.NewCommand(set)
	return cmd.Execute()
}

func configFlag() string {
	// Default config path; overridden by --config flag
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return "file:./examples/otelcol-config.yaml"
}
