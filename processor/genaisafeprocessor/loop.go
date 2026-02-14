// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: Apache-2.0

package genaisafeprocessor

import (
	"regexp"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// detectSimpleLoop checks if any tool-like span name repeats
// more than `threshold` times within a batch, which is a
// cheap heuristic for runaway agent loops.
func detectSimpleLoop(spans ptrace.SpanSlice, toolRe *regexp.Regexp, threshold int) bool {
	if threshold <= 0 {
		threshold = 6
	}
	counts := make(map[string]int)
	for i := 0; i < spans.Len(); i++ {
		name := spans.At(i).Name()
		if toolRe != nil && toolRe.MatchString(name) {
			counts[name]++
			if counts[name] >= threshold {
				return true
			}
		}
	}
	return false
}
