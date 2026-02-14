FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -o /otelcol-genai-safe ./cmd/otelcol-custom

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /otelcol-genai-safe /otelcol-genai-safe
ENTRYPOINT ["/otelcol-genai-safe"]
