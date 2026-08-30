# ai-cve-finder-agent

## How to run

Setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the repo root with whichever of these you have:

```
GITHUB_TOKEN=...      # required for GHSA source + commit/issue/PR scanning
NVD_API_KEY=...       # optional, raises the NVD rate limit
ANTHROPIC_API_KEY=... # required if using the claude LLM provider
GROQ_API_KEY=...      # required if using the groq LLM provider
OLLAMA_HOST=...       # optional, defaults to localhost — only for the ollama provider
```

Commands:

### `scan`
Run the known-CVE pipeline (NVD + OSV.dev + GHSA), then the pre-CVE commit scanner + LLM triage, for watchlist packages.

| Option | Description |
|---|---|
| `--packages TEXT` | Scan specific packages only (repeatable) |
| `--layer [framework\|sdk\|mcp\|infrastructure]` | Scan one layer only |
| `--dry-run` | Run the pipeline but do not write findings to the database |
| `--llm-provider TEXT` | Override the triage LLM provider for this run (`groq`\|`claude`\|`ollama`) |
| `--llm-model TEXT` | Override the triage LLM model for this run |

### `scan-status`
Show per-package checkpoint progress for a `scan` run — safe to run mid-scan.

| Option | Description |
|---|---|
| `--run-id INTEGER` | Show a specific run (default: most recent) |

### `scan-repo`
One-off scan of a single package/repo, not read from or written to `config/watchlist.yaml`.

| Option | Description |
|---|---|
| `--name TEXT` | **Required.** Package name — used for finding IDs, not persisted anywhere |
| `--ecosystem [pypi\|npm]` | **Required.** |
| `--layer [framework\|sdk\|mcp\|infrastructure]` | **Required.** |
| `--repo TEXT` | **Required.** GitHub org/repo, e.g. `org/repo` |
| `--agentic-context TEXT` | Optional free-text context for the LLM |
| `--dry-run` | Run the pipeline but do not write findings to the database |
| `--llm-provider TEXT` | Override the triage LLM provider for this run (`groq`\|`claude`\|`ollama`) |
| `--llm-model TEXT` | Override the triage LLM model for this run |

### `watch`
Process the Lane 2 watch queue — re-triage findings whose 48h re-check is due.

| Option | Description |
|---|---|
| `--dry-run` | Run the re-check but do not write changes to the database |
| `--llm-provider TEXT` | Override the triage LLM provider for this run (`groq`\|`claude`\|`ollama`) |
| `--llm-model TEXT` | Override the triage LLM model for this run |

### `hunt`
Run the pattern hunter: scan watchlist packages' source for every pattern in `patterns/library.json`.

| Option | Description |
|---|---|
| `--packages TEXT` | Hunt against specific packages only (repeatable) |
| `--layer [framework\|sdk\|mcp\|infrastructure]` | Hunt one layer only |
| `--dry-run` | Run the hunt but do not write findings to the database |
| `--llm-provider TEXT` | Override the `pattern_hunt` LLM provider for this run |
| `--llm-model TEXT` | Override the `pattern_hunt` LLM model for this run |

### `disclose`
Mark a finding as disclosed. Does not change the 90-day CVE filing deadline (already set at first Lane 1A triage).

| Option | Description |
|---|---|
| `--finding-id TEXT` | **Required.** |
| `--to TEXT` | **Required.** Maintainer email or GitHub issue URL |

### `report`
Re-runs the pre-file cross-check gate on every Lane 1 finding not yet `ready_to_file`, then generates a Markdown report from current database state.

| Option | Description |
|---|---|
| `--output TEXT` | Report output path (default: `reports/YYYY-MM-DD.md`) |
| `--llm-provider TEXT` | Override the `cve_drafting` LLM provider for this run |
| `--llm-model TEXT` | Override the `cve_drafting` LLM model for this run |

### `validate`
Phase 7 dynamic validation — strictly on-demand, one finding at a time, requires a local Docker daemon.

| Option | Description |
|---|---|
| `--finding-id TEXT` | **Required.** |
| `--class [path_traversal\|command_injection\|sql_injection\|deserialization\|ssrf\|arbitrary_file_rw]` | Run one of the six fixed exploit harnesses instead of the default pattern-confirmation depth |
| `--target-module TEXT` | `--class` only: dotted module path to import inside the sandbox |
| `--target-callable TEXT` | `--class` only: dot-separated attribute path to the vulnerable callable |
| `--target-param TEXT` | `--class` only: keyword arg the injected value goes in (omit for a positional call) |
| `--target-mode [read\|write]` | `--class arbitrary_file_rw` only: which primitive to probe (default: `write`) |
| `--version TEXT` | Exact affected version to install (default: auto-resolved) |
| `--force` | Required to run `--class` against a finding whose recorded CWE doesn't match that class |

### `audit`
Standalone agentic-tooling security-posture audit against a repo's source (clone → read → delete). Never touches Finding/lane/status/disclosure.

| Option | Description |
|---|---|
| `--repo TEXT` | **Required.** GitHub org/repo to audit, e.g. `org/repo` |
| `--ecosystem [pypi\|npm]` | **Required.** |
| `--areas TEXT` | Specific checklist area(s) to check, repeatable — choices: `tool_authorization`, `unsafe_default_permissions`, `path_traversal`, `token_exposure`, `subprocess_arg_injection`, `mcp_trust_boundaries`, `workspace_isolation` (see `config/audit_checklist.yaml`) |
| `--all` | Check every area in `config/audit_checklist.yaml` |
| `--output TEXT` | Report output path (default: `reports/audit-{org}-{repo}-YYYY-MM-DD.md`) |
| `--dry-run` | Run the audit but do not write `audit_runs` rows |
| `--llm-provider TEXT` | Override the `agentic_audit` LLM provider for this run |
| `--llm-model TEXT` | Override the `agentic_audit` LLM model for this run |

### `status`
Print a summary of finding counts by lane and status. No options.

### `watchlist`
List all watchlist packages with their layer and enabled status. No options.

Run `python3 main.py <command> --help` for this same detail from the CLI itself.

Run tests with:

```bash
pytest
```