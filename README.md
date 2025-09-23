# DevSecOpsBot Image Scanner

A GitHub Action that scans container images for **vulnerabilities** and **secrets** . Includes built‑in **blocking policies**, **CI/CD integration**, and optional reporting to the [DevSecOpsBot dashboard](https://devsecops.bot).

---

## 🚀 Features

* 🔍 Scan container images for **vulnerabilities** and **secrets**
* 🛠️ Works in **GitHub Actions CI** and **locally** with `scanner.py`
* 🛡️ Flexible **blocking policies**: block on critical, high+critical, any vulnerability, or secrets
* ☁️ Supports multiple registry providers: **AWS ECR, GCP Artifact Registry, Azure ACR, Docker Hub, generic private registries**
* 📦 Produces both **tabular CLI output** and **structured JSON** for backend ingestion
* 🧾 Detects CI context and attaches **GitHub metadata** to scan results
* 📤 Optionally **POST results** to a backend for dashboards and audit trails

---

## 📊 Dashboard

![Dashboard](images/dashboard.png)

Sign up at [https://devsecops.bot](https://devsecops.bot) to get your **free token** and send results to the backend dashboard.

---

## 📦 Usage

### GitHub Actions workflow

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
      - uses: devsecopsbot/image-scan@v0.0.2
        with:
          image: ${{ github.event.inputs.image }}
          post-url: ${{ secrets.POST_URL }}
          auth-token: ${{ secrets.AUTH_TOKEN }}
        env:
          BLOCK_ON_CRITICAL: 0
          BLOCK_ON_HIGH: 10
          BLOCK_ON_ANY: false
          BLOCK_ON_SECRETS: true
```

### Local usage

```bash
# Scan an image locally
python scanner.py nginx:latest

# Block if any critical vulnerabilities exist
BLOCK_ON_CRITICAL=0 python scanner.py nginx:latest

# Send results to backend
POST_URL=https://api.devsecops.bot AUTH_TOKEN=yourtoken python scanner.py myimage:tag
```

---

## 🔧 Configuration

### Backend

* `POST_URL` – backend endpoint (e.g., `https://api.devsecops.bot/api/scan`)
* `AUTH_TOKEN` – backend auth token (obtain from [devsecops.bot](https://devsecops.bot))

### Blocking Policies

* `BLOCK_ON_CRITICAL` – block if critical vulns exceed threshold (e.g., `0`)
* `BLOCK_ON_HIGH` – block if high+critical vulns exceed threshold (e.g., `10`)
* `BLOCK_ON_ANY` – block if *any* vulnerability exists (`true/false`)
* `BLOCK_ON_SECRETS` – block if any secrets are detected (`true/false`)

### Registry Options

* `REGISTRY_TOKEN` – token for registry auth
* `REGISTRY_USERNAME`, `REGISTRY_PASSWORD` – generic registry credentials
* `REGISTRY_AZURE_USERNAME`, `REGISTRY_AZURE_PASSWORD` – Azure registry credentials
* `BASE64_GOOGLE_CREDENTIALS` – base64-encoded Google service account JSON
* `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` – AWS IAM credentials for ECR

---

## ☁️ Cloud Registries

### AWS Elastic Container Registry (ECR)

Authenticate using IAM credentials or roles:

```bash
export AWS_ACCESS_KEY_ID=xxxx
export AWS_SECRET_ACCESS_KEY=yyyy
export AWS_REGION=us-east-1
python scanner.py <aws_account_id>.dkr.ecr.us-east-1.amazonaws.com/myimage:tag
```

### Google Artifact Registry / GCR

Provide service account JSON encoded as base64:

```bash
export BASE64_GOOGLE_CREDENTIALS=$(cat key.json | base64)
python scanner.py gcr.io/myproject/myimage:tag
```

### Azure Container Registry (ACR)

Use registry-specific username/password:

```bash
export REGISTRY_AZURE_USERNAME=<username>
export REGISTRY_AZURE_PASSWORD=<password>
python scanner.py myregistry.azurecr.io/myimage:tag
```


---

## 📤 Output

### Console Output

* 🔐 Secrets found
* 🛡️ Vulnerability summary (counts by severity)
* 🔥 Top 10 vulnerabilities
* 📦 SBOM summary (components, dependencies)

### Backend Output (if configured)

```json
{
  "image_uri": "nginx:latest",
  "source": "CI",
  "source_info": {
    "provider": "github",
    "repo_full_name": "devsecopsbot/image-scan",
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

## 🛡️ Blocking Behavior

The Action **exits with code 1** if any configured blocking policy is triggered, failing the job.

Examples:

* `BLOCK_ON_CRITICAL=0` → fail if *any* critical vuln exists
* `BLOCK_ON_HIGH=5` → fail if more than 5 high+critical vulns
* `BLOCK_ON_ANY=true` → fail if any vuln exists
* `BLOCK_ON_SECRETS=true` → fail if any secrets found

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

If `POST_URL` and `AUTH_TOKEN` are not set, the scanner prints results in tabular format to the console:

![Tabular Output](images/tabular.png)

Useful for local testing and debugging without backend integration.

---
