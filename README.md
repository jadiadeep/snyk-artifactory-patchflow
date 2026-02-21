# snyk-artifactory-patchflow

**Snyk-driven dependency upgrades gated by JFrog Artifactory, with Patchwork DependencyUpgrade + AutoFix.**

Automate dependency upgrades from [Snyk](https://snyk.io) vulnerability reports by choosing **only** versions that exist in your [JFrog Artifactory](https://jfrog.com/artifactory/). Apply uses [Patchwork](https://github.com/patched-codes/patchwork) [DependencyUpgrade](https://github.com/patched-codes/patchwork/tree/main/patchwork/patchflows/DependencyUpgrade) and [AutoFix](https://github.com/patched-codes/patchwork/tree/main/patchwork/patchflows/AutoFix) as part of the flow.

- **Python 3.11+**
- **Input:** Snyk JSON from `snyk test --json` (or upload via FastAPI).
- **Output:** `out/upgrade_summary.json` and `out/upgrade_summary.md`.

**Repository:** [github.com/jadiadeep/snyk-artifactory-patchflow](https://github.com/jadiadeep/snyk-artifactory-patchflow)

---

## How to run

Replace the sample report with your real one, then run.

1. **Get your Snyk report** (from your app repo):  
   `snyk test --json > snyk-report.json`
2. **Run** (from this repo or anywhere):
   ```bash
   dep-patchflow plan snyk-report.json
   dep-patchflow apply snyk-report.json --project-dir /path/to/your/app
   ```

You can ignore `sample_snyk_report.json`—it’s only for trying the CLI. Use your own `snyk-report.json` (or any filename) and pass it to `plan` / `apply`.

See **Simple flow** below for install and config.

---

## Why Artifactory? Version rule

All upgrade versions **must** exist in Artifactory so your environment can actually download them.

- If Snyk’s requested fix version **is** in Artifactory → we use it.
- If Snyk’s requested version **is not** in Artifactory → we use the **latest available in Artifactory** (so the tool can still install something).  
  **Example:** Snyk asks to update to 3.9, but Artifactory only has up to 3.7 → we use 3.7 instead of 3.9.

---

## Patchwork (DependencyUpgrade + AutoFix)

Apply runs two Patchwork patchflows (both used by default):

1. **[DependencyUpgrade](https://github.com/patched-codes/patchwork/tree/main/patchwork/patchflows/DependencyUpgrade)** — dependency upgrade flow (aligns with our Artifactory-gated plan).
2. **[AutoFix](https://github.com/patched-codes/patchwork/tree/main/patchwork/patchflows/AutoFix)** — vulnerability/code fixes (e.g. Semgrep-based).

Set `openai_api_key` in `defaults.yml` (or env) for apply. Use `--no-patchwork` only to skip running Patchwork and only update manifest files.

---

## Simple flow

### 1. Install

```bash
git clone https://github.com/jadiadeep/snyk-artifactory-patchflow.git
cd snyk-artifactory-patchflow
pip install -e .
pip install 'patchwork-cli[security]'   # required for apply (DependencyUpgrade + AutoFix)
```

### 2. Config

Edit **`defaults.yml`**. Set when you have them:

| Key | What to put |
|-----|-------------|
| `artifactory_base_url` | Your Artifactory URL (e.g. `https://your-company.jfrog.io/artifactory`) |
| `openai_api_key` | LLM API key (e.g. OpenAI) — **required for apply** (Patchwork) |

You can leave them empty to only run `plan`; without Artifactory URL, version resolution is skipped (items listed as “skipped”). Without the LLM key, apply will update manifests but Patchwork steps will fail unless you use `--no-patchwork`.

### 3. Snyk report

From your app project (where `requirements.txt` or `package.json` lives):

```bash
snyk test --json > snyk-report.json
```

### 4. Run

**Plan** (recommended first):

```bash
dep-patchflow plan snyk-report.json
```

**Apply** (update manifests, then run Patchwork DependencyUpgrade and AutoFix):

```bash
dep-patchflow apply snyk-report.json --project-dir /path/to/your/app
```

Use `--no-patchwork` to only update `requirements.txt` / `package.json` and skip Patchwork.

---

## defaults.yml

Single config file. Set Artifactory URL and LLM key when available.

- **Artifactory:** `artifactory_base_url`, and if needed `artifactory_token` (or username/password).
- **LLM (Patchwork):** `openai_api_key` — required when running apply (DependencyUpgrade + AutoFix); never hardcoded in code.

Optional: `artifactory_repo_pypi`, `artifactory_repo_npm`, `artifactory_version_method` (`aql` or `metadata`), and a `policy:` block (e.g. `allow_major`, `min_severity`, `dry_run`). See `defaults.yml` in the repo for the full template.

---

## FastAPI (optional)

```bash
uvicorn dep_patchflow.api:app --host 0.0.0.0 --port 8000
```

- **GET /health** — Liveness.
- **POST /scan-report** — Upload Snyk JSON → returns plan.
- **POST /apply** — Upload Snyk JSON and apply (manifests + Patchwork DependencyUpgrade + AutoFix).

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
  version_policy.py  # Latest in Artifactory when Snyk version not available
  planner.py
  patchwork_runner.py # DependencyUpgrade + AutoFix
  reporting.py
  api.py             # FastAPI
tests/
out/                 # upgrade_summary.json, upgrade_summary.md
```

## Pushing to GitHub

If you cloned this repo and made changes, or need to push:

```bash
cd snyk-artifactory-patchflow
git add .
git commit -m "Your message"
git push -u origin main
```

If `git commit` fails with an error about `trailer`, try `git -c commit.gpgsign=false commit -m "Your message"`.

## License

MIT. See [LICENSE](LICENSE).
