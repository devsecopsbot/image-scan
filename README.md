# DevSecOpsBot Image Scanner

GitHub Action to scan container images for **vulnerabilities** and **secrets** using [Trivy](https://github.com/aquasecurity/trivy), with built-in **blocking policies** and optional **backend reporting** to [devsecops.bot](https://devsecops.bot).

---

## 🚀 Features

* Scans container images with Trivy (`vuln,secret` scanners)
* Supports **GitHub Actions CI** and **local CLI** usage (`scanner.py`)
* Flexible **blocking policies** (critical, high+critical, any vuln, secrets)
* Supports multiple registry auth methods (token, Azure, GCP, AWS, generic)
* Detects CI context and tags results with GitHub metadata
* Optionally **POST results to backend** for visibility and dashboards

---

## 📊 Dashboard

![Dashboard](images/dashboard.png)

Sign up at [https://devsecops.bot](https://devsecops.bot) to get your **free token** and start sending results to the backend.

---

## 📦 Usage

### Basic workflow

```yaml
name: Image Scan

on:
  workflow_dispatch:
    inputs:
      image:
        description: "Image to scan"
        required: true
        default: "nginx:latest"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: devsecopsbot/image-scan@v1
        with:
          image: ${{ github.event.inputs.image }}
        env:
          AUTH_TOKEN: ${{ secrets.AUTH_TOKEN }}
          POST_URL: ${{ secrets.POST_URL }}
          BLOCK_ON_CRITICAL: 0
          BLOCK_ON_HIGH: 10
          BLOCK_ON_ANY: false
          BLOCK_ON_SECRETS: true
```

### Local usage

```bash
# Scan an image locally
python scanner.py nginx:latest

# Block if any critical vulnerabilities
BLOCK_ON_CRITICAL=0 python scanner.py nginx:latest

# Send results to backend
POST_URL=https://api.devsecops.bot AUTH_TOKEN=yourtoken python scanner.py myimage:tag
```

---

## 🔧 Environment Variables

### Backend

* `POST_URL` – backend endpoint (e.g., `https://api.devsecops.bot/api/scan`)
* `AUTH_TOKEN` – auth token (get one at [devsecops.bot](https://devsecops.bot))

### Blocking Options

* `BLOCK_ON_CRITICAL` – block if critical vulns exceed threshold (e.g., `0`)
* `BLOCK_ON_HIGH` – block if high+critical vulns exceed threshold (e.g., `10`)
* `BLOCK_ON_ANY` – block if any vulnerability is found (`true/false`)
* `BLOCK_ON_SECRETS` – block if secrets are detected (`true/false`)

### Registry Options

* `REGISTRY_TOKEN` – single token for registry auth
* `REGISTRY_USERNAME`, `REGISTRY_PASSWORD` – generic registry credentials
* `REGISTRY_AZURE_USERNAME`, `REGISTRY_AZURE_PASSWORD` – Azure registry credentials
* `BASE64_GOOGLE_CREDENTIALS` – base64-encoded Google credentials (json)

### Trivy Cache

* `TRIVY_CACHE_DIR` – cache directory for Trivy DB (defaults to `~/.cache/trivy` locally, `.cache/trivy` in GitHub Actions)

---

## ☁️ Cloud Registries

### AWS ECR

Trivy can use your standard AWS credentials (from environment or IAM role). Example:

```bash
export AWS_ACCESS_KEY_ID=xxxx
export AWS_SECRET_ACCESS_KEY=yyyy
export AWS_REGION=us-east-1
python scanner.py <aws_account_id>.dkr.ecr.us-east-1.amazonaws.com/myimage:tag
```

### Google Artifact Registry / GCR

Provide base64 encoded service account JSON:

```bash
export BASE64_GOOGLE_CREDENTIALS=$(cat key.json | base64)
python scanner.py gcr.io/myproject/myimage:tag
```

### Azure Container Registry (ACR)

Provide registry-specific username/password:

```bash
export REGISTRY_AZURE_USERNAME=<username>
export REGISTRY_AZURE_PASSWORD=<password>
python scanner.py myregistry.azurecr.io/myimage:tag
```

---

## 📤 Output

### Console Output

* Secrets found
* Vulnerability summary (counts by severity)
* Top 10 vulnerabilities
* SBOM summary (components, dependencies)

### Backend Output (if `POST_URL` + `AUTH_TOKEN` set)

```json
{
  "image_uri": "nginx:latest",
  "source": "CI",
  "source_info": {
    "provider": "github",
    "repo_full_name": "sttor/devsecopsbot",
    "workflow": "Image Scan",
    "run_id": "123456",
    "run_number": "42"
  },
  "scan_output": {
    "report": { ... },
    "sbom": { ... }
  }
}
```

---

## 🛡️ Blocking behavior

The Action will **exit with code 1** if any blocking policy is triggered. This will fail the GitHub Actions job, preventing further steps (useful in CI pipelines).

Examples:

* `BLOCK_ON_CRITICAL=0` → fail if *any* critical vuln exists.
* `BLOCK_ON_HIGH=5` → fail if more than 5 high+critical vulns.
* `BLOCK_ON_ANY=true` → fail if any vuln exists.
* `BLOCK_ON_SECRETS=true` → fail if any secrets found.

---

## 📖 Examples

### Fail build on any vulnerability

```yaml
env:
  BLOCK_ON_ANY: true
```

### Fail build if >5 high/critical vulns

```yaml
env:
  BLOCK_ON_HIGH: 5
```

### Upload results to backend

```yaml
env:
  POST_URL: https://api.devsecops.bot/api/scan
  AUTH_TOKEN: ${{ secrets.AUTH_TOKEN }}
```

---

## 📑 Without Backend (Tabular Console Mode)

If you don’t configure `POST_URL` and `AUTH_TOKEN`, the scanner prints results in **tabular format** directly to console:

![Tabular Output](images/tabular.png)

This mode is ideal for local testing and debugging.

---
