# User Guide: snyk-artifactory-patchflow

Complete step-by-step guide to set up and run the snyk-artifactory-patchflow tool.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Getting Your Snyk Report](#getting-your-snyk-report)
5. [Running the Tool](#running-the-tool)
6. [Project Requirements](#project-requirements)
7. [Environment Variables (Alternative)](#environment-variables-alternative)
8. [Understanding Output](#understanding-output)
9. [Troubleshooting](#troubleshooting)
10. [Security Best Practices](#security-best-practices)

---

## Prerequisites

Before you begin, ensure you have the following:

### Required

1. **Python 3.11 or higher**
   - Check your version: `python --version` or `python3 --version`
   - Download from [python.org](https://www.python.org/downloads/) if needed

2. **Snyk CLI installed and authenticated**
   - Install: `npm install -g snyk` (requires Node.js) or download from [snyk.io](https://docs.snyk.io/snyk-cli/install-the-snyk-cli)
   - Authenticate: `snyk auth` (follow the prompts)

3. **Access to JFrog Artifactory**
   - Your Artifactory base URL (e.g., `https://your-company.jfrog.io/artifactory`)
   - Authentication token or username/password
   - Repository names for PyPI and npm (if different from defaults)

4. **OpenAI API Key** (required for `apply` command)
   - Get your API key from [OpenAI Platform](https://platform.openai.com/api-keys)
   - Required for Patchwork DependencyUpgrade and AutoFix features

### Optional

- Git (for cloning the repository)
- A project with `requirements.txt` (Python) or `package.json` (Node.js) to upgrade

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/jadiadeep/snyk-artifactory-patchflow.git
cd snyk-artifactory-patchflow
```

### Step 2: Install the Tool

```bash
# Install the tool itself
pip install -e .

# Install Patchwork CLI (required for apply command)
pip install 'patchwork-cli[security]'
```

**Note:** If you encounter permission errors, use `pip install --user -e .` or use a virtual environment:

```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Then install
pip install -e .
pip install 'patchwork-cli[security]'
```

### Step 3: Verify Installation

```bash
dep-patchflow --help
```

You should see the CLI help menu with `plan` and `apply` commands.

---

## Configuration

### Step 1: Edit `defaults.yml`

Open `defaults.yml` in the project root directory. This file contains all configuration settings.

### Step 2: Configure Artifactory

Set your Artifactory connection details:

```yaml
# Artifactory base URL
artifactory_base_url: "https://your-company.jfrog.io/artifactory"

# Authentication (choose one method)
# Option 1: Token (recommended)
artifactory_token: "your-artifactory-token-here"

# Option 2: Username and Password (uncomment if using)
# artifactory_username: "your-username"
# artifactory_password: "your-password"

# Repository names (adjust if your repos have different names)
artifactory_repo_pypi: "pypi-remote"  # Your PyPI repository name
artifactory_repo_npm: "npm-remote"     # Your npm repository name

# Version listing method: "aql" (default) or "metadata"
artifactory_version_method: "aql"
```

**How to get your Artifactory token:**
1. Log into Artifactory
2. Go to your user profile → Edit Profile → Authentication
3. Generate an API key or access token
4. Copy the token to `defaults.yml`

### Step 3: Configure OpenAI API Key

```yaml
# LLM API key for Patchwork (required for apply command)
openai_api_key: "sk-your-openai-api-key-here"
```

**Important:** Never commit `defaults.yml` with real credentials to Git. See [Security Best Practices](#security-best-practices) below.

### Step 4: Configure Policy (Optional)

You can customize upgrade behavior:

```yaml
# Policy (optional overrides)
policy:
  allow_major: false              # Allow major version upgrades (default: false)
  min_severity: "medium"          # Minimum severity: low, medium, high, critical
  max_upgrades_per_run: 20        # Maximum number of upgrades per run
  prefer_stable_only: true        # Only use stable versions (default: true)
  dry_run: false                 # Preview changes without applying (default: false)
```

### Complete Example `defaults.yml`

```yaml
# dep-patchflow defaults — edit this file when you have credentials.

# Artifactory base URL
artifactory_base_url: "https://mycompany.jfrog.io/artifactory"

# Artifactory auth: set one of token or username+password
artifactory_token: "AKCp5dK..."
# artifactory_username: ""
# artifactory_password: ""

# Repo keys for version listing
artifactory_repo_pypi: "pypi-remote"
artifactory_repo_npm: "npm-remote"
artifactory_version_method: "aql"

# LLM API key for Patchwork (required for apply)
openai_api_key: "sk-..."

# Optional: path to Patchwork's default.yml if you use a custom one
# patchwork_default_yml_path: "default.yml"

# Policy (optional overrides)
policy:
  allow_major: false
  min_severity: "medium"
  max_upgrades_per_run: 20
  prefer_stable_only: true
  dry_run: false
```

---

## Getting Your Snyk Report

### Step 1: Navigate to Your Project

Go to the directory containing your project's dependency files (`requirements.txt` for Python or `package.json` for Node.js):

```bash
cd /path/to/your/project
```

### Step 2: Authenticate with Snyk (if not already done)

```bash
snyk auth
```

Follow the prompts to authenticate via your browser.

### Step 3: Generate Snyk Report

Run Snyk test and save the JSON output:

```bash
snyk test --json > snyk-report.json
```

**For Python projects:**
```bash
snyk test --file=requirements.txt --json > snyk-report.json
```

**For Node.js projects:**
```bash
snyk test --file=package.json --json > snyk-report.json
```

### Step 4: Verify the Report

Check that the file was created and contains data:

```bash
# On Windows (PowerShell)
Get-Content snyk-report.json | ConvertFrom-Json | Select-Object -First 1

# On macOS/Linux
head -20 snyk-report.json
```

The report should contain a `vulnerabilities` array with package information.

**Note:** You can use the sample report (`sample_snyk_report.json`) for testing, but replace it with your real report for actual upgrades.

---

## Running the Tool

### Command: `plan` (Recommended First Step)

The `plan` command analyzes your Snyk report and creates an upgrade plan without making any changes.

```bash
dep-patchflow plan snyk-report.json
```

**What it does:**
- Parses your Snyk vulnerability report
- Checks which fix versions are available in Artifactory
- Creates an upgrade plan showing what will be upgraded
- Generates two output files:
  - `out/upgrade_summary.json` (machine-readable)
  - `out/upgrade_summary.md` (human-readable)

**Example output:**
```
Plan generated.
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━work DependencyUpgrade then AutoFix...
Done.
```

**Options:**
- `--project-dir` or `-d`: Specify the project directory (default: current directory)
- `--no-patchwork`: Skip Patchwork execution, only update manifest files
- `--config` or `-c`: Use a different config file instead of `defaults.yml`

**Example with options:**
```bash
# Apply upgrades to a specific project directory
dep-patchflow apply snyk-report.json --project-dir /path/to/my-project

# Only update manifest files, skip Patchwork
dep-patchflow apply snyk-report.json --no-patchwork

# Use a custom config file
dep-patchflow apply snyk-report.json --config my-config.yml
```

---

## Project Requirements

For the `apply` command to work, your target project directory must contain:

### Python Projects
- `requirements.txt` file in the project root
- The tool will update package versions in this file

### Node.js Projects
- `package.json` file in the project root
- The tool will update versions in `dependencies` and `devDependencies`

**Note:** The tool only updates existing packages. It does not add new dependencies.

---

## Environment Variables (Alternative)

Instead of editing `defaults.yml`, you can set environment variables. Environment variables take precedence over `defaults.yml`.

### Artifactory Settings

```bash
# Windows (PowerShell)
$env:ARTIFACTORY_BASE_URL="https://your-company.jfrog.io/artifactory"
$env:ARTIFACTORY_TOKEN="your-token"

# Windows (CMD)
set ARTIFACTORY_BASE_URL=https://your-company.jfrog.io/artifactory
set ARTIFACTORY_TOKEN=your-token

# macOS/Linux
export ARTIFACTORY_BASE_URL="https://your-company.jfrog.io/artifactory"
export ARTIFACTORY_TOKEN="your-token"
```

### OpenAI API Key

```bash
# Windows (PowerShell)
$env:OPENAI_API_KEY="sk-your-key"

# macOS/Linux
export OPENAI_API_KEY="sk-your-key"
```

### Policy Settings

```bash
# Windows (PowerShell)
$env:POLICY_ALLOW_MAJOR="false"
$env:POLICY_MIN_SEVERITY="medium"
$env:POLICY_MAX_UPGRADES_PER_RUN="20"
$env:POLICY_DRY_RUN="false"

# macOS/Linux
export POLICY_ALLOW_MAJOR="false"
export POLICY_MIN_SEVERITY="medium"
export POLICY_MAX_UPGRADES_PER_RUN="20"
export POLICY_DRY_RUN="false"
```

### Using `.env` File

You can also create a `.env` file in the project root (it's automatically loaded):

```env
ARTIFACTORY_BASE_URL=https://your-company.jfrog.io/artifactory
ARTIFACTORY_TOKEN=your-token
OPENAI_API_KEY=sk-your-key
POLICY_MIN_SEVERITY=medium
POLICY_DRY_RUN=false
```

**Important:** Add `.env` to `.gitignore` to avoid committing secrets!

---

## Understanding Output

### Plan Output Files

After running `plan`, you'll find two files in the `out/` directory:

1. **`upgrade_summary.json`** - Machine-readable JSON with:
   - List of upgrades (package, from version, to version, ecosystem, reason)
   - List of skipped items (package, reason)
   - Metadata (Snyk report path, config path, timestamp)

2. **`upgrade_summary.md`** - Human-readable markdown report with:
   - Summary statistics
   - Detailed upgrade list
   - Skipped items explanation

### Console Output

The console shows:
- A table of planned upgrades
- Number of skipped items
- Paths to output files

### Apply Output

The `apply` command shows:
- Which manifest files were updated
- Patchwork execution status
- Any errors or warnings

---

## Troubleshooting

### Issue: "All items skipped / no upgrades"

**Possible causes:**
1. Artifactory URL not configured
2. Artifactory authentication failed
3. No vulnerabilities meet the minimum severity threshold
4. Snyk report is empty or invalid

**Solutions:**
- Check `defaults.yml` has `artifactory_base_url` set
- Verify Artifactory token/credentials are correct
- Lower `min_severity` in policy (try `"low"`)
- Verify Snyk report contains vulnerabilities: `snyk test --json | grep -i vulnerability`

### Issue: "Patchwork not found"

**Solution:**
```bash
pip install 'patchwork-cli[security]'
```

Verify installation:
```bash
patchwork --help
```

### Issue: "Artifactory returns no versions"

**Possible causes:**
1. Repository name mismatch
2. Package not available in Artifactory
3. Wrong version listing method

**Solutions:**
- Check repository names in `defaults.yml` match your Artifactory setup
- Try switching `artifactory_version_method` from `"aql"` to `"metadata"` (or vice versa)
- Verify the package exists in your Artifactory repository

### Issue: "OPENAI_API_KEY not set"

**Solution:**
- Set `openai_api_key` in `defaults.yml`, or
- Set `OPENAI_API_KEY` environment variable, or
- Use `--no-patchwork` flag to skip Patchwork execution

### Issue: "Snyk report not found"

**Solution:**
- Verify the file path is correct
- Use absolute path: `dep-patchflow plan /full/path/to/snyk-report.json`
- Check file exists: `ls snyk-report.json` (macOS/Linux) or `dir snyk-report.json` (Windows)

### Issue: "Permission denied" when installing

**Solution:**
Use a virtual environment or `--user` flag:
```bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -e .
```

### Issue: "Invalid JSON in Snyk report"

**Solution:**
- Regenerate the Snyk report: `snyk test --json > snyk-report.json`
- Check the file is valid JSON: `python -m json.tool snyk-report.json`

### Issue: "Manifest files not updated"

**Possible causes:**
1. No upgrades in plan
2. Manifest file not found in project directory
3. Package name mismatch

**Solutions:**
- Run `plan` first to see what upgrades are planned
- Verify `requirements.txt` or `package.json` exists in `--project-dir`
- Check package names match exactly (case-sensitive)

---

## Security Best Practices

### 1. Never Commit Secrets

**DO NOT commit `defaults.yml` with real credentials to Git.**

The `.gitignore` file already excludes:
- `config.yml`
- `.env`
- `.env.local`

**Recommended approach:**
- Keep `defaults.yml` with empty values in the repo
- Use environment variables for secrets in production
- Or create a local `config.yml` (already in `.gitignore`)

### 2. Use Environment Variables in CI/CD

In CI/CD pipelines, use environment variables instead of config files:

```yaml
# Example GitHub Actions
env:
  ARTIFACTORY_BASE_URL: ${{ secrets.ARTIFACTORY_BASE_URL }}
  ARTIFACTORY_TOKEN: ${{ secrets.ARTIFACTORY_TOKEN }}
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### 3. Rotate Credentials Regularly

- Rotate Artifactory tokens periodically
- Regenerate OpenAI API keys if compromised
- Use least-privilege tokens (scope tokens to only needed repositories)

### 4. Review Upgrades Before Applying

Always run `plan` first and review `out/upgrade_summary.md` before running `apply`:

```bash
# Review the plan
dep-patchflow plan snyk-report.json
cat out/upgrade_summary.md

# If satisfied, apply
dep-patchflow apply snyk-report.json --project-dir /path/to/project
```

### 5. Use Dry Run Mode

Test changes without applying them:

```yaml
# In defaults.yml
policy:
  dry_run: true
```

Or via environment variable:
```bash
export POLICY_DRY_RUN=true
dep-patchflow apply snyk-report.json
```

---

## Quick Reference

### Common Commands

```bash
# Install
pip install -e .
pip install 'patchwork-cli[security]'

# Generate Snyk report
snyk test --json > snyk-report.json

# Plan upgrades
dep-patchflow plan snyk-report.json

# Apply upgrades
dep-patchflow apply snyk-report.json --project-dir /path/to/project

# Apply without Patchwork
dep-patchflow apply snyk-report.json --no-patchwork

# Use custom config
dep-patchflow plan snyk-report.json --config my-config.yml
```

### Configuration Checklist

- [ ] Python 3.11+ installed
- [ ] Snyk CLI installed and authenticated
- [ ] `defaults.yml` configured with Artifactory URL
- [ ] Artifactory token/credentials set
- [ ] OpenAI API key set (for `apply` command)
- [ ] Repository names match your Artifactory setup
- [ ] Policy settings configured (optional)

### File Locations

- **Config:** `defaults.yml` (project root)
- **Snyk Report:** `snyk-report.json` (anywhere, specify path)
- **Output:** `out/upgrade_summary.json` and `out/upgrade_summary.md`
- **Target Project:** Must contain `requirements.txt` or `package.json`

---

## Getting Help

- **Repository:** [github.com/jadiadeep/snyk-artifactory-patchflow](https://github.com/jadiadeep/snyk-artifactory-patchflow)
- **Issues:** Open an issue on GitHub if you encounter bugs
- **Documentation:** See `README.md` for technical details

---

## Next Steps

1. ✅ Install the tool
2. ✅ Configure `defaults.yml`
3. ✅ Generate your Snyk report
4. ✅ Run `plan` to see what will be upgraded
5. ✅ Review `out/upgrade_summary.md`
6. ✅ Run `apply` to upgrade dependencies
7. ✅ Test your application
8. ✅ Commit changes to version control

Happy upgrading! 🚀
