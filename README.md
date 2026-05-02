# lint-in-the-dead

A distributed code-quality and compliance engine. Scans repositories for security vulnerabilities, quality issues, license conflicts, and secret leakage — in a single CLI invocation or as a full microservice platform.

---

## Quick start

```bash
# Scan the current directory in-process (no services needed)
go build -o litd ./cmd/litd/
./litd check .

# With GitHub Actions annotations and custom rules
./litd check . --format gh --rules configs/rules --fail-on high
```

---

## Architecture

```
┌─────────┐     ┌─────────────┐     ┌──────────────────┐
│  litd   │────▶│ api-gateway │────▶│ analysis-service │
│  (CLI)  │     │  :8080      │     │  :8082           │
└─────────┘     └─────────────┘     └──────────────────┘
                      │                      │
                      ▼                      ▼
               ┌─────────────┐     ┌──────────────────┐
               │policy-engine│     │  audit-service   │
               │  :8081      │     │  :8083           │
               └─────────────┘     └──────────────────┘
                                            │
                                            ▼
                                   ┌──────────────────┐
                                   │notification-svc  │
                                   │  :8084           │
                                   └──────────────────┘
```

### Services

| Service | Port | Responsibility |
|---|---|---|
| `api-gateway` | 8080 | Job intake, WebSocket hub, SSE broker, GitHub webhooks |
| `policy-engine` | 8081 | YAML rule loading and regex evaluation |
| `analysis-service` | 8082 | Worker pool: clone → analyse → score → fan-out |
| `audit-service` | 8083 | Immutable HMAC-signed audit log (Postgres or in-memory) |
| `notification-service` | 8084 | Slack and email delivery |

---

## CLI reference

```
litd <command> [flags]

Commands:
  check    Run full analysis in-process (no services required)
  scan     Submit a repository to the running platform
  jobs     List completed analysis results
  job      Show a single job result
  audit    Query the immutable audit log
  rules    List loaded policy rules
  health   Check health of all services
  version  Print version
```

### `litd check`

Runs the complete pipeline locally — useful for CI, pre-commit hooks, or self-analysis.

```
litd check [directory] [flags]

Flags:
  --rules string            Directory containing YAML rule files (default: configs/rules)
  --format string           Output format: text | gh | json  (default: text)
  --entropy-threshold float Shannon entropy threshold for secret detection (default: 4.5)
  --max-findings int        Limit output to N findings (0 = unlimited)
  --no-entropy              Disable entropy-based secret scanning
  --no-deps                 Disable dependency lockfile scanning
  --fail-on string          Minimum severity for non-zero exit: critical|high|medium|low|never (default: high)
```

**Format `gh`** emits GitHub Actions workflow commands so findings appear as inline PR annotations:
```
::error file=pkg/foo.go,line=12,col=1,title=[SEC-001] Hardcoded secret::Possible secret detected
```

---

## GitHub Actions

Add to any workflow to self-check the repository:

```yaml
- name: Build litd
  run: go build -o litd ./cmd/litd/

- name: litd check
  run: ./litd check . --rules configs/rules --format gh --fail-on high --no-entropy
```

The repository ships a pre-built workflow at [`.github/workflows/litd.yml`](.github/workflows/litd.yml) that runs on every push and PR against `main`.

---

## Rule DSL

Rules live in `configs/rules/*.yaml`:

```yaml
rules:
  - id: SEC-001
    name: Hardcoded secret
    enabled: true
    category: security
    severity: critical          # critical | high | medium | low | info
    languages: ["*"]            # "*" matches any language
    pattern:
      type: regex               # regex | literal | negate
      match: '(?i)(password|secret|token)\s*=\s*["''][^"'']{8,}["'']'
    message: Possible hardcoded secret
    fix_suggestion: Use environment variables or a secrets manager.
```

Built-in rule sets:

| File | Rules | Focus |
|---|---|---|
| `security.yaml` | 8 | Hardcoded secrets, eval, SQL injection, weak crypto, hardcoded IPs |
| `quality.yaml` | 8 | Debug prints, panic, ignored errors, magic numbers, nesting depth |
| `license.yaml` | 2 | GPL detection, missing SPDX header |

---

## Analysers

| Analyser | Detects |
|---|---|
| **Rule engine** | Violations matching YAML regex/literal/negate patterns |
| **Entropy scanner** | High-entropy strings likely to be secrets (Shannon ≥ 4.5, length ≥ 12) |
| **Dep scanner** | Unpinned dependencies in go.mod, package.json, requirements.txt, Cargo.toml, pom.xml |

---

## Scoring

```
score = 100
      − 20 × critical_count
      − 10 × high_count
      −  5 × medium_count
      −  1 × low_count
(clamped to [0, 100])

passed = score ≥ 70
```

---

## Running the full platform

```bash
# Start everything (Postgres + 5 services + Prometheus + Grafana)
docker compose up -d

# Submit a scan job
./litd scan --repo https://github.com/org/repo --sha abc123 --wait

# View results
./litd jobs
./litd job <job-id>
./litd audit --job <job-id>
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `LITD_GATEWAY` | `http://localhost:8080` | API gateway URL |
| `LITD_ANALYSIS_URL` | `http://localhost:8082` | Analysis service URL |
| `LITD_POLICY_URL` | `http://localhost:8081` | Policy engine URL |
| `LITD_AUDIT_URL` | `http://localhost:8083` | Audit service URL |
| `LITD_NOTIF_URL` | `http://localhost:8084` | Notification service URL |
| `DATABASE_URL` | *(unset → in-memory)* | Postgres DSN for audit log |
| `GITHUB_TOKEN` | *(optional)* | Enables GitHub Check Runs and PR comments |
| `SLACK_WEBHOOK_URL` | *(optional)* | Enables Slack notifications |
| `HMAC_SECRET` | `changeme` | Signing key for audit log entries |

---

## Observability

- Every service exposes **Prometheus metrics** at `/metrics`
- **Grafana dashboard** at `http://localhost:3000` (provisioned automatically)
- **Audit trail**: every job event is HMAC-signed and stored immutably

---

## Development

```bash
# Run all tests
cd pkg           && go test ./...
cd tests/integration && go test ./... -v

# Build all services
for svc in services/*/; do (cd "$svc" && go build ./...); done

# Build CLI
go build -o litd ./cmd/litd/
```

Go 1.24 workspace (`go.work`) ties all modules together — no need to `replace` directives in individual `go.mod` files during development.

---

## License

MIT

---

Built by [Voxire](https://voxire.com) — digital agency in Beirut, Lebanon.
