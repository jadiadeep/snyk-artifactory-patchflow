# snyk-artifactory-patchflow

**Snyk-driven dependency upgrades gated by JFrog Artifactory, with optional Patchwork apply.**

Automate dependency upgrades from [Snyk](https://snyk.io) vulnerability reports by choosing **only** versions that exist in your [JFrog Artifactory](https://jfrog.com/artifactory/). Optionally use [Patchwork](https://github.com/patched-codes/patchwork) to apply upgrades and autofix.

- **Python 3.11+**
- **Input:** Snyk JSON from `snyk test --json` (or upload via FastAPI).
- **Output:** `out/upgrade_summary.json` and `out/upgrade_summary.md`.

**Repository:** [github.com/jadiadeep/snyk-artifactory-patchflow](https://github.com/jadiadeep/snyk-artifactory-patchflow)

---

## How to run

```bash
git clone https://github.com/jadiadeep/snyk-artifactory-patchflow.git
cd snyk-artifactory-patchflow
pip install -e .
# Optional: edit defaults.yml with artifactory_base_url and openai_api_key when available
snyk test --json > snyk-report.json    # from your app repo
dep-patchflow plan snyk-report.json
dep-patchflow apply snyk-report.json --project-dir /path/to/your/app
```

See **Simple flow** below for details.

---

## Why Artifactory?

Snyk may recommend fix versions your org doesn’t mirror. This tool only picks versions that exist in Artifactory so you can install them from your own repos.

---

## Simple flow

### 1. Install

```bash
git clone https://github.com/jadiadeep/snyk-artifactory-patchflow.git
cd snyk-artifactory-patchflow
pip install -e .
```

### 2. Config (no blocker)

Edit **`defaults.yml`** in the project root. When you have credentials, set:

| Key | What to put |
|-----|-------------|
| `artifactory_base_url` | Your Artifactory URL (e.g. `https://your-company.jfrog.io/artifactory`) |
| `openai_api_key` | Your LLM API key (e.g. OpenAI) when you want to run Patchwork |

You can leave them **empty**. The tool still runs: it parses the Snyk report and writes a plan; without Artifactory URL it skips version resolution (listed as “skipped” with a reason). Without the LLM key, only the Patchwork apply step is affected.

### 3. Snyk report

From your app project (where `requirements.txt` or `package.json` lives):

```bash
snyk test --json > snyk-report.json
```

### 4. Run

**Plan only** (recommended first):

```bash
dep-patchflow plan snyk-report.json
```

If `defaults.yml` exists in the current directory, it’s used automatically. Otherwise:

```bash
dep-patchflow plan snyk-report.json --config path/to/defaults.yml
```

**Apply** (update manifests and optionally run Patchwork):

```bash
dep-patchflow apply snyk-report.json --project-dir .
```

Use `--no-patchwork` to only update `requirements.txt` / `package.json` and skip Patchwork.

---

## defaults.yml

Single config file. Set Artifactory URL and LLM key when available.

- **Artifactory:** `artifactory_base_url`, and if needed `artifactory_token` (or username/password).
- **LLM (Patchwork):** `openai_api_key` — used when running Patchwork for apply; never hardcoded in code.

Optional: `artifactory_repo_pypi`, `artifactory_repo_npm`, `artifactory_version_method` (`aql` or `metadata`), and a `policy:` block (e.g. `allow_major`, `min_severity`, `dry_run`). See `defaults.yml` in the repo for the full template.

---

## FastAPI (optional)

```bash
uvicorn dep_patchflow.api:app --host 0.0.0.0 --port 8000
```

- **GET /health** — Liveness.
- **POST /scan-report** — Upload Snyk JSON → returns plan.
- **POST /apply** — Upload Snyk JSON and apply (manifests + optional Patchwork).

API reads settings from environment variables (e.g. `ARTIFACTORY_BASE_URL`, `OPENAI_API_KEY`).

---

## Security

- **No secrets in code.** URL and LLM key go in `defaults.yml` (or env). Don’t commit real credentials; add `defaults.yml` to `.gitignore` if you store secrets in it.
- Patchwork receives the LLM key from config/env at runtime; it’s never hardcoded.

---

## Troubleshooting

- **All items skipped / no upgrades**  
  Set `artifactory_base_url` (and auth) in `defaults.yml`. Check `min_severity` and that the Snyk report has vulns.

- **Patchwork not found**  
  `pip install 'patchwork-cli[security]'`. Run from the project directory you want to patch.

- **Artifactory returns no versions**  
  Repo layout may differ; try `artifactory_version_method: "metadata"` or adjust paths in `artifactory.py` for your setup.

---

## Tests

```bash
pytest tests/ -v
```

---

## Project layout

```
defaults.yml          ← Edit: Artifactory URL + LLM key when available
config.example.yml   ← Reference only
src/dep_patchflow/
  main.py            # CLI: plan | apply
  config.py          # Loads defaults.yml
  models.py
  snyk_parser.py
  artifactory.py
  version_policy.py
  planner.py
  patchwork_runner.py
  reporting.py
  api.py             # FastAPI
tests/
out/                 # upgrade_summary.json, upgrade_summary.md
```

## License

MIT. See [LICENSE](LICENSE).
