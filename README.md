# opentelemetry-collector-processor-genai

An OpenTelemetry Collector processor for AI safety: PII redaction, infinite loop detection, and token metrics for LLM traces.

## Features

### PII Redaction
Redacts sensitive content in LLM prompts and completions using configurable strategies:
- **hash_and_preview**: Keeps first N characters + SHA-256 hash (default)
- **full_hash**: Replaces entire value with hash
- **Denylist patterns**: Automatically redacts API keys, tokens, and authorization headers

### Loop Detection
Tracks repeated identical prompts per trace to detect infinite loops. When `repeat_threshold` is exceeded, adds `gen_ai.loop_detected=true` and `gen_ai.loop_count` attributes.

### Token Metrics
Calculates `gen_ai.usage.total_tokens` from input + output token counts and marks processed spans with `gen_ai.safe.processed=true`.

## Configuration

```yaml
processors:
  genaisafe:
    redact:
      mode: hash_and_preview
      preview_chars: 48
      salt: your-secret-salt
      keys:
        - gen_ai.prompt
        - gen_ai.completion
      denylist_regex:
        - "(?i)api[_-]?key"
        - "(?i)sk-[a-z0-9]{20,}"
    metrics:
      enable: true
    loop_detection:
      enable: true
      repeat_threshold: 6
```

## Part of the AIR Platform

This processor is one component of the [AIR Blackbox Gateway](https://github.com/nostalgicskinco/air-blackbox-gateway) collector pipeline.

## License

Apache-2.0