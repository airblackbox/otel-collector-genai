// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: Apache-2.0

package genaisafeprocessor

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// redactSpan applies configured redaction rules to a single span.
func (p *genAIProc) redactSpan(s ptrace.Span) {
	attrs := s.Attributes()

	// 1) Redact configured keys (prompt/completion text)
	for _, key := range p.cfg.Redact.Keys {
		v, ok := attrs.Get(key)
		if !ok || v.Type() != pcommon.ValueTypeStr {
			continue
		}
		applyRedaction(attrs, key, v.Str(), p.cfg.Redact)
	}

	// 2) Generic denylist scrub across all string attributes
	attrs.Range(func(k string, v pcommon.Value) bool {
		if v.Type() != pcommon.ValueTypeStr {
			return true
		}
		val := v.Str()
		for _, re := range p.denylist {
			if re.MatchString(k) || re.MatchString(val) {
				attrs.PutStr(k, "[REDACTED]")
				break
			}
		}
		return true
	})
}

// applyRedaction replaces a single attribute value based on
// the configured redaction mode (drop, hash, truncate, hash_and_preview).
func applyRedaction(attrs pcommon.Map, key, orig string, cfg RedactConfig) {
	trim := strings.TrimSpace(orig)
	if trim == "" {
		return
	}

	hash := sha256.Sum256([]byte(cfg.Salt + "::" + trim))
	h := hex.EncodeToString(hash[:])

	switch cfg.Mode {
	case "drop":
		attrs.Remove(key)
		attrs.PutStr(key+".hash", h)
	case "hash":
		attrs.PutStr(key, "[HASHED]")
		attrs.PutStr(key+".hash", h)
	case "truncate":
		attrs.PutStr(key, truncate(trim, cfg.PreviewChars))
		attrs.PutStr(key+".hash", h)
	default: // hash_and_preview
		attrs.PutStr(key, truncate(trim, cfg.PreviewChars))
		attrs.PutStr(key+".hash", h)
	}
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
