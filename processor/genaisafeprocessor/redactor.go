package genaisafeprocessor

import (
	"crypto/sha256"
	"fmt"
	"regexp"
)

// Redactor handles PII and sensitive data redaction.
type Redactor struct {
	mode         string
	previewChars int
	salt         string
	denylist     []*regexp.Regexp
}

// NewRedactor creates a redactor from config.
func NewRedactor(cfg RedactConfig) (*Redactor, error) {
	var patterns []*regexp.Regexp
	for _, p := range cfg.DenylistRegex {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid denylist regex %q: %w", p, err)
		}
		patterns = append(patterns, re)
	}

	return &Redactor{
		mode:         cfg.Mode,
		previewChars: cfg.PreviewChars,
		salt:         cfg.Salt,
		denylist:     patterns,
	}, nil
}

// Redact applies the redaction strategy to a string value.
func (r *Redactor) Redact(value string) string {
	// First, redact any denylist matches
	redacted := value
	for _, re := range r.denylist {
		redacted = re.ReplaceAllString(redacted, "[REDACTED]")
	}

	switch r.mode {
	case "hash_and_preview":
		return r.hashAndPreview(redacted)
	case "full_hash":
		return r.fullHash(redacted)
	default:
		return r.hashAndPreview(redacted)
	}
}

// ContainsSensitive checks if a string matches any denylist pattern.
func (r *Redactor) ContainsSensitive(value string) bool {
	for _, re := range r.denylist {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func (r *Redactor) hashAndPreview(value string) string {
	hash := sha256.Sum256([]byte(r.salt + value))
	hexHash := fmt.Sprintf("%x", hash)[:16]

	preview := value
	if len(preview) > r.previewChars {
		preview = preview[:r.previewChars]
	}

	return fmt.Sprintf("%s...[sha256:%s]", preview, hexHash)
}

func (r *Redactor) fullHash(value string) string {
	hash := sha256.Sum256([]byte(r.salt + value))
	return fmt.Sprintf("[sha256:%x]", hash)
}