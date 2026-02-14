# otelcol-genai-safe

**Privacy-by-default OpenTelemetry Collector processor for GenAI workloads.**

Your AI agents talk to LLMs. Those LLM calls produce traces full of prompts, completions, API keys, and cost data. This processor sits inside your OTel Collector and makes those traces safe before they hit your observability backend.

No SDK changes. No app code modifications. Just add it to your collector pipeline.

---

## What it does

**1. Redacts sensitive GenAI data**

Prompts and completions are hashed, truncated, or dropped — configurable per attribute. Secret patterns (API keys, bearer tokens) are scrubbed automatically.

```
BEFORE (raw span attribute):
  gen_ai.prompt: "Summarize this contract. The API key is sk-abc123def456..."

AFTER (processed by genaisafe):
  gen_ai.prompt: "Summarize this contract. The API key is sk-ab…"
  gen_ai.prompt.hash: "a1b2c3d4e5f6..."
```

**2. Extracts cost and token metrics**

Pulls `prompt_tokens`, `completion_tokens`, and `cost_usd` from spans. Normalizes attribute names so your dashboards work regardless of which SDK your team uses.

```
BEFORE:
  llm.usage.prompt_tokens: 150
  llm.usage.completion_tokens: 89

AFTER (added by genaisafe):
  genai.tokens.prompt: 150
  genai.tokens.completion: 89
  genai.tokens.total: 239
```

**3. Detects runaway agent loops**

When a tool span repeats 6+ times in a batch, every span in that scope gets flagged:

```
genai.risk.loop_suspected: true
```

Alert on this in Grafana/Datadog/PagerDuty before your agent burns through your API budget.

---

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/nostalgicskinco/opentelemetry-collector-processor-genai.git
cd opentelemetry-collector-processor-genai
docker compose -f examples/docker-compose.yaml up --build
```

This starts the collector + Jaeger. Send traces to `localhost:4317` (gRPC) or `localhost:4318` (HTTP). View results at [http://localhost:16686](http://localhost:16686).

### Build from source

```bash
go build -o otelcol-genai-safe ./cmd/otelcol-custom
./otelcol-genai-safe --config examples/otelcol-config.yaml
```

---

## Configuration

Add `genaisafe` to your collector's `processors` section:

```yaml
processors:
  genaisafe:
    redact:
      mode: "hash_and_preview"   # drop | hash | hash_and_preview | truncate
      preview_chars: 48
      salt: "your-secret-salt"
      keys:
        - "gen_ai.prompt"
        - "gen_ai.completion"
      denylist_regex:
        - "(?i)sk-[a-z0-9]{20,}"
        - "(?i)api[_-]?key"
    metrics:
      enable: true
      emit_interval: "10s"
    loop_detection:
      enable: true
      repeat_threshold: 6
```

### Redaction modes

| Mode | What happens | Use case |
|------|-------------|----------|
| `drop` | Attribute removed, hash preserved | Strict compliance (HIPAA, SOC2) |
| `hash` | Value replaced with `[HASHED]`, hash preserved | Correlation without exposure |
| `hash_and_preview` | First N chars kept + hash | Debugging with safety (default) |
| `truncate` | First N chars kept + hash | Similar to hash_and_preview |

---

## Architecture

```
Your App (SDK)
    |
    | OTLP traces with raw prompts, tokens, costs
    v
┌─────────────────────────────────┐
│  OTel Collector                 │
│  ┌───────────────────────────┐  │
│  │  genaisafe processor      │  │
│  │  - redact prompts/secrets │  │
│  │  - extract token metrics  │  │
│  │  - detect agent loops     │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
    |
    | Clean traces (no secrets, normalized metrics)
    v
Jaeger / Datadog / Grafana Tempo
```

## Why collector-side?

SDK-level redaction means every team, every language, every framework has to get it right. One missed integration and you're leaking PII into your tracing backend.

Collector-side processing catches everything uniformly. Deploy once, protect all teams.

---

## Threat model

This processor protects against:

- **Accidental PII in prompts** — user data passed to LLMs ends up in your tracing backend. Redaction prevents this from reaching storage.
- **Leaked API keys** — agents that pass credentials through tool calls. Denylist regex catches common patterns.
- **Runaway agent loops** — an agent stuck calling the same tool burns API budget. Loop detection flags this for alerting.
- **Cost visibility gaps** — different SDKs use different attribute names. Normalized metrics give you one dashboard.

This processor does NOT protect against:
- Malicious insiders with collector access
- Side-channel attacks on hashed values (use a strong salt)
- Perfect PII detection (MVP uses regex patterns, not ML models)

---

## Roadmap

- [x] MVP: redaction, metrics extraction, loop detection
- [ ] Real trace-to-metrics emission (OTel connector)
- [ ] Per-trace loop detection (not just per-batch)
- [ ] Structured PII masking (JSON-path aware)
- [ ] YAML allowlist/denylist policies per attribute path
- [ ] Grafana dashboard template
- [ ] Helm chart for Kubernetes deployment

---

## Contributing

PRs welcome. The codebase is intentionally small — one processor, ~500 lines of Go.

```bash
# Run tests
go test ./...

# Build
go build ./cmd/otelcol-custom
```

---

## License

Apache 2.0
