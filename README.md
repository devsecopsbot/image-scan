# DevSecOpsBot Image Scanner

A GitHub Action that scans container images for **vulnerabilities** and **secrets**, with built-in **blocking policies**, **CI/CD integration**, and optional reporting to the [DevSecOpsBot dashboard](https://devsecops.bot).

---

## 🚀 Features

* 🔍 Scans container images for **vulnerabilities** and **secrets**
* 🛠️ Runs natively inside **GitHub Actions CI**
* 🛡️ Flexible **blocking policies**: block on critical, high+critical, any vulnerability, or secrets
* ☁️ Supports **AWS ECR**, **GCP Artifact Registry**, **Azure ACR**, **Docker Hub**, and private registries
* 📦 Produces both **tabular CLI output** (for CI logs) and **structured JSON** (for backend ingestion)
* 🯞 Automatically detects **GitHub metadata** for each CI run
* 📤 Optionally **POSTs results** to a backend for dashboards and audit trails

---

## 📊 Dashboard

![Dashboard](images/dashboard.png)

Sign up at [https://devsecops.bot](https://devsecops.bot) to get your **free token** and view your organization’s scan results in the DevSecOpsBot dashboard.

---

## 📦 Usage

### GitHub Actions Workflow

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
          post-url: ${{ secrets.POST_URL }}
          auth-token: ${{ secrets.AUTH_TOKEN }}
          server-token: ${{ secrets.SERVER_TOKEN }}
          block-on-critical: 0
          block-on-high: 10
          block-on-any: false
          block-on-secrets: true
```

---

## 🔧 Configuration

### Backend

* `post-url` – backend endpoint (e.g., `https://api.devsecops.bot/api/scan`)
* `auth-token` – backend authentication token (from [devsecops.bot](https://devsecops.bot))
* `server-token` – vulnerability DB token (from [devsecops.bot](https://devsecops.bot))

### Blocking Policies

* `block-on-critical` – block if critical vulns exceed threshold (e.g., `0`)
* `block-on-high` – block if high+critical vulns exceed threshold (e.g., `10`)
* `block-on-any` – block if *any* vulnerability exists (`true/false`)
* `block-on-secrets` – block if any secrets are detected (`true/false`)

> Configure these inputs directly in your GitHub Actions workflow.

---

## ☁️ Cloud Registry Authentication

### AWS Elastic Container Registry (ECR)

```yaml
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  AWS_REGION: us-east-1
```

### Google Artifact Registry / GCR

```yaml
env:
  BASE64_GOOGLE_CREDENTIALS: ${{ secrets.BASE64_GOOGLE_CREDENTIALS }}
```

### Azure Container Registry (ACR)

```yaml
env:
  REGISTRY_AZURE_USERNAME: ${{ secrets.REGISTRY_AZURE_USERNAME }}
  REGISTRY_AZURE_PASSWORD: ${{ secrets.REGISTRY_AZURE_PASSWORD }}
```

---

## 📤 Output

### CI Console Output

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

The Action **exits with code 1** if any configured blocking policy is triggered, failing the CI job.

Examples:

* `block-on-critical: 0` → fail if *any* critical vuln exists
* `block-on-high: 5` → fail if more than 5 high+critical vulns
* `block-on-any: true` → fail if any vuln exists
* `block-on-secrets: true` → fail if any secrets found

---

## 🔖 Examples

### Fail build on any vulnerability

```yaml
with:
  block-on-any: true
```

### Fail build if >5 high/critical vulns

```yaml
with:
  block-on-high: 5
```

### Upload results to backend

```yaml
with:
  post-url: https://api.devsecops.bot/api/scan
  auth-token: ${{ secrets.AUTH_TOKEN }}
  server-token: ${{ secrets.SERVER_TOKEN }}
```

👉 See a full working workflow here: [test-image-scan.yml](https://github.com/devsecopsbot/test-image-scan/blob/main/.github/workflows/test-image-scan.yml)

---

## 💑 Console Mode (CI Logs)

If `post-url` and `auth-token` are not provided, results are printed directly to the **GitHub Actions logs** in tabular format:

![Tabular Output](images/tabular.png)
