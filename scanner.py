import os, sys, json, base64, tempfile, subprocess, time
import requests
import random
from tabulate import tabulate


def prepare_trivy_env():
    env = dict(os.environ)
    if env.get("REGISTRY_TOKEN"):
        return
    if env.get("REGISTRY_USERNAME") and env.get("REGISTRY_PASSWORD"):
        os.environ["TRIVY_USERNAME"] = env["REGISTRY_USERNAME"]
        os.environ["TRIVY_PASSWORD"] = env["REGISTRY_PASSWORD"]
        return
    if env.get("BASE64_GOOGLE_CREDENTIALS"):
        try:
            decoded = base64.b64decode(env["BASE64_GOOGLE_CREDENTIALS"]).decode("utf-8")
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
                f.write(decoded)
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = f.name
        except Exception as e:
            print(f"⚠️ Failed to decode Google credentials: {e}")
        return
    if env.get("REGISTRY_AZURE_USERNAME") and env.get("REGISTRY_AZURE_PASSWORD"):
        os.environ["TRIVY_USERNAME"] = env["REGISTRY_AZURE_USERNAME"]
        os.environ["TRIVY_PASSWORD"] = env["REGISTRY_AZURE_PASSWORD"]


def run_trivy(image):
    server = random.choices([1,2])[0]
    prepare_trivy_env()
    cache_dir = os.getenv("TRIVY_CACHE_DIR", os.path.expanduser("~/.cache/trivy"))
    base_cmd = ["trivy", "image", image, "--cache-dir", cache_dir]

    if os.getenv("SERVER_TOKEN"):
        base_cmd += ["--server", f"https://vulndb{server}.devsecops.bot", "--token", os.environ["SERVER_TOKEN"], "--token-header", "X-Server-Token"]

    if os.getenv("REGISTRY_TOKEN"):
        base_cmd += ["--registry-token", os.environ["REGISTRY_TOKEN"]]

    scan_cmd = base_cmd + [
        "--detection-priority", "precise",
        "--scanners", "vuln,secret",
        "--format", "json"
    ]

    # SBOM generation without vuln info
    sbom_cmd = base_cmd + [
        "--format", "cyclonedx"
    ]



    def run_cmd(cmd):
        try:
            r = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return json.loads(r.stdout)
        except subprocess.CalledProcessError as e:
            print(f"❌ Trivy command failed: {' '.join(cmd)}")
            print(f"stderr: {e.stderr.strip()}")
            return None
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse JSON output: {e}")
            return None

    report = run_cmd(scan_cmd)
    sbom = run_cmd(sbom_cmd)
    return {"report": report, "sbom": sbom}


def enforce_block_policy(report):

    results = report.get("Results", []) if report else []
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    secrets = []

    for item in results:
        if item.get("Class") == "secret":
            secrets.extend(item.get("Secrets", []))
        else:
            for v in item.get("Vulnerabilities", []) or []:
                sev = v.get("Severity", "UNKNOWN").upper()
                counts[sev] = counts.get(sev, 0) + 1

    crit, high = counts["CRITICAL"], counts["HIGH"]
    total = sum(counts.values())
    bc, bh, ba, bs = os.getenv("BLOCK_ON_CRITICAL"), os.getenv("BLOCK_ON_HIGH"), os.getenv("BLOCK_ON_ANY"), os.getenv("BLOCK_ON_SECRETS")

    message = "Build Successful"
    exit_code = 0
    if bc and crit > int(bc):
        message = f"❌ Blocking: {crit} critical vulnerabilities > threshold {bc}"
        exit_code = 1

    if bh and crit + high > int(bh):
        message = f"❌ Blocking: {crit+high} high/critical vulnerabilities > threshold {bh}"
        exit_code = 1

    if ba and ba.lower() in ["1", "true", "yes"] and total > 0:
        message = f"❌ Blocking: {total} vulnerabilities found"
        exit_code = 1

    if bs and bs.lower() in ["1", "true", "yes"] and secrets:
        message = f"❌ Blocking: {len(secrets)} secrets detected"
        exit_code = 1


    return exit_code, message

def get_source_info():
    if os.getenv("GITHUB_ACTIONS") == "true":
        return "CI", {
            "provider": "github",
            "repo_full_name": os.getenv("GITHUB_REPOSITORY", ""),
            "workflow": os.getenv("GITHUB_WORKFLOW", ""),
            "run_id": os.getenv("GITHUB_RUN_ID", ""),
            "run_number": os.getenv("GITHUB_RUN_NUMBER", ""),
            "branch": os.getenv("GITHUB_REF", ""),
            "commit": os.getenv("GITHUB_SHA", ""),
            "actor": os.getenv("GITHUB_ACTOR", ""),
            "event": os.getenv("GITHUB_EVENT_NAME", ""),
            "pr_head": os.getenv("GITHUB_HEAD_REF", ""),
            "pr_base": os.getenv("GITHUB_BASE_REF", "")
        }
    return "CLI", {}


def print_summary_table(report, sbom):
    vuln_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    try:
        results = report.get("Results", []) if report else []
        secrets, top_vulns = [], []

        for item in results:
            if item.get("Class") == "secret":
                for sec in item.get("Secrets", []):
                    secrets.append({
                        "target": item.get("Target"),
                        "title": sec.get("Title"),
                        "severity": sec.get("Severity")
                    })
            else:
                for vuln in item.get("Vulnerabilities", []):
                    sev = vuln.get("Severity", "UNKNOWN").upper()
                    vuln_counts[sev] = vuln_counts.get(sev, 0) + 1
                    top_vulns.append({
                        "severity": sev,
                        "id": vuln.get("VulnerabilityID"),
                        "pkg": vuln.get("PkgName"),
                        "title": vuln.get("Title")
                    })

        print("\n🔐 Secrets Found:")
        if secrets:
            print(tabulate([[s["target"], s["title"], s["severity"]] for s in secrets], headers=["Target", "Title", "Severity"], tablefmt="grid"))
        else:
            print("No secrets found.")

        print("\n🛡️ Vulnerability Summary:")
        print(tabulate([[k, v] for k, v in vuln_counts.items()], headers=["Severity", "Count"], tablefmt="grid"))

        print("\n🔥 Top 10 Vulnerabilities:")
        top_sorted = sorted(top_vulns, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].index(x["severity"]))
        print(tabulate([[v["severity"], v["id"], v["pkg"], v["title"]] for v in top_sorted[:10]], headers=["Severity", "ID", "Package", "Title"], tablefmt="grid"))

        if sbom:
            print("\n📦 SBOM Summary:")
            components = len(sbom.get("components", []))
            deps = len(sbom.get("dependencies", []))
            print(f"Components: {components}, Dependencies: {deps}")

    except Exception as e:
        print(f"⚠️ Failed to parse summary: {e}")

    return vuln_counts


def main(image):
    data = run_trivy(image)
    source, source_info = get_source_info()
    report, sbom = data.get("report"), data.get("sbom")
    url, token = os.getenv("POST_URL"), os.getenv("AUTH_TOKEN")
    url = url.strip("/") + "/api/container/scan/output/"
    summary = print_summary_table(report, sbom)
    exit_code, message = enforce_block_policy(report)
    print(message)
    source_info["exit_code"] = exit_code
    source_info["stats"] = summary
    source_info["message"] = message

    if url and token and report:
        headers = {"Authorization": token, "Content-Type": "application/json"}
        payload = {"image_uri": image, "source": source, "source_info": source_info,
                  "scan_output": {"report": report, "sbom": sbom}}
        for i in range(3):
            try:
                r = requests.post(url, headers=headers, data=json.dumps(payload))
                print(f"Attempt {i+1}: POST returned status {r.status_code}")
                if r.status_code < 400:
                    break
            except Exception as e:
                print(f"Attempt {i+1}: POST failed with error: {e}")
            time.sleep(2 * (i + 1))

    if exit_code:
        sys.exit(exit_code)







def print_helper():
    print("""
Usage: scanner <image>

Environment Variables / Options:
  POST_URL            URL of backend to upload scan results. Example: https://myserver/api/scan
  AUTH_TOKEN          Auth token for backend. Example: secret123
  SERVER_TOKEN        Token to access vulnerability database.

Blocking Options (exit 1 if triggered):
  BLOCK_ON_CRITICAL   Block if critical vulns exceed threshold. Example: 0
  BLOCK_ON_HIGH       Block if high+critical vulns exceed threshold. Example: 10
  BLOCK_ON_ANY        Block if any vulnerability found. Values: true/false
  BLOCK_ON_SECRETS    Block if any secret found. Values: true/false

Registry Options:
  REGISTRY_TOKEN              Single token for registry auth.
  REGISTRY_USERNAME, REGISTRY_PASSWORD          Generic registry credentials.
  REGISTRY_AZURE_USERNAME, REGISTRY_AZURE_PASSWORD   Azure registry credentials.
  BASE64_GOOGLE_CREDENTIALS   Base64 encoded Google credentials.

Performance / Server:
  TRIVY_CACHE_DIR     Cache directory for Trivy DB. Example: ~/.cache/trivy

Examples:
  scanner myapp:latest
  BLOCK_ON_CRITICAL=0 scanner myapp:latest
  POST_URL=https://api.devsecops.bot AUTH_TOKEN=abc123 scanner myapp:latest
""")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help", "help"]:
        print_helper()
        sys.exit(0)
    main(sys.argv[1])
