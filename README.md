<p align="center">
  <img src="logo.png" alt="Gradle Guard" width="150"/>
</p>

<h1 align="center">Gradle Guard</h1>

<p align="center">
  <strong>🛡️ Dependency vulnerability scanner for Java Gradle projects</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#multi-module-support">Multi-Module</a> •
  <a href="#json-reports">JSON Reports</a> •
  <a href="#license">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue?logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/gradle-compatible-02303A?logo=gradle&logoColor=white" alt="Gradle"/>
  <img src="https://img.shields.io/badge/OSV-API-green?logo=opensourceinitiative&logoColor=white" alt="OSV API"/>
  <img src="https://img.shields.io/badge/license-MIT-yellow" alt="License"/>
</p>

---

**Gradle Guard** is a lightweight Python CLI that scans your Gradle project's resolved dependency tree and checks every artifact against the [OSV.dev](https://osv.dev/) vulnerability database. It reports known CVEs, suggests upgrade paths, and can export results as JSON for CI integration.

## Features

- **🔍 Automatic dependency resolution** — Resolved dependency tree.
- **📦 Multi-module support** — Scans all submodules at once via a single Gradle task.
- **🌐 OSV.dev integration** — Batch queries the OSV API for the Maven ecosystem.
- **⚡ Severity classification** — Vulnerabilities sorted by CRITICAL → HIGH → MEDIUM → LOW.
- **✅ Upgrade recommendations** — Shows all available fix versions per vulnerability.
- **📄 JSON export** — Machine-readable reports for CI/CD pipelines and dashboards.
- **🎨 Rich terminal output** — Color-coded, human-friendly reports with CVE cross-references.
- **🌳 Gradle dependency tree** — Optional ANSI tree preserving parent-child transitive paths and highlighting vulnerable nodes.
- **🪟 Cross-platform** — Works on Windows, macOS, and Linux.

## Installation

### Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.8+ |
| pip package | `requests` |
| Java - Gradle | Wrapper (`gradlew`) recommended |

### Setup

```bash
# 1. Clone
git clone https://github.com/argorar/gradle_guard.git

# 2. (Optional) Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # macOS / Linux
.venv\Scripts\activate      # Windows

# 3. Install dependencies
pip install requests
```

## Usage

### Basic Scan

```bash
# macOS / Linux
python gradle_guard.py ~/projects/my-spring-app

# Windows
python gradle_guard.py C:\Users\me\projects\my-spring-app
```

### Export JSON Report

```bash
python gradle_guard.py ~/projects/my-spring-app --json report.json
```

### Print Gradle Dependency Tree With Vulnerabilities

```bash
python gradle_guard.py ~/projects/my-spring-app --tree
```

Use `--tree-all-configs` to print every Gradle configuration instead of the deduplicated tree.

### Example Output

```
════════════════════════════════════════════════════════════════════════════════
  🛡️  VULNERABILITY SCAN REPORT
════════════════════════════════════════════════════════════════════════════════
  Scanned                  : 87
  Vulnerable dependencies  : 5
  Vulns                    : 12
════════════════════════════════════════════════════════════════════════════════

  📦 org.springframework:spring-web:5.3.20

     [HIGH] GHSA-xxxx-yyyy-zzzz (CVE-2023-XXXXX)
     Spring Framework vulnerable to denial of service...
     ✅ Upgrade alternatives: 5.3.28, 6.0.10

  ────────────────────────────────────────────────────────────────────────────

  📋 RECOMMENDED UPGRADES
  ────────────────────────────────────────────────────────────────────────────
  Library                                       Current        Upgrade Alternatives
  ────────────────────────────────────────────────────────────────────────────
  org.springframework:spring-web                5.3.20         5.3.28, 6.0.10
  ────────────────────────────────────────────────────────────────────────────
```

## Multi-Module Support

Gradle Guard works with multi-module projects out of the box. To enable full scanning, register the `allDeps` task in your root `build.gradle` (or `main.gradle`):

```groovy
allprojects {
    tasks.register("allDeps", DependencyReportTask) {}
}
```

Gradle Guard will then execute:

```bash
./gradlew allDeps -q --no-daemon
```

This collects the complete dependency tree across **all submodules** in a single pass.

## JSON Reports

The `--json` flag produces a structured report suitable for dashboards, CI gates, or further processing:

```json
{
  "scan_date": "2026-05-13T21:30:00-0500",
  "total": 87,
  "vulnerable": 5,
  "results": [
    {
      "coordinate": "org.springframework:spring-web:5.3.20",
      "vulnerabilities": [
        {
          "id": "GHSA-xxxx-yyyy-zzzz",
          "aliases": ["CVE-2023-XXXXX"],
          "severity": "HIGH",
          "summary": "Spring Framework vulnerable to denial of service...",
          "fixed_versions": ["5.3.28", "6.0.10"]
        }
      ]
    }
  ]
}
```

## How It Works

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Gradle Project  │────▶│  ./gradlew       │────▶│  Dependency  │
│  (your code)     │     │  allDeps -q      │     │  Tree        │
└──────────────────┘     └──────────────────┘     └──────┬───────┘
                                                         │
                                                         ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Terminal Report │◀────│  Parse & Match   │◀────│  OSV.dev API │
│  + JSON Export   │     │  Vulnerabilities │     │  (batch)     │
└──────────────────┘     └──────────────────┘     └──────────────┘
```

1. **Discover** — Locates `build.gradle`, `build.gradle.kts`, or `main.gradle` files.
2. **Resolve** — Executes the Gradle `allDeps` task to obtain the real resolved dependency versions (including transitive dependencies and version overrides).
3. **Query** — Sends batch requests to the [OSV.dev API](https://osv.dev/) for the Maven ecosystem.
4. **Enrich** — Fetches detailed vulnerability data, extracts severity, CVE aliases, fix versions, and references.
5. **Report** — Renders a color-coded terminal report sorted by severity, with an upgrade summary table.


## CI/CD Integration

Gradle Guard can be integrated into your pipeline. Example with **GitHub Actions**:

```yaml
- name: Scan dependencies
  run: |
    pip install requests
    python gradle_guard.py . --json vulnerability-report.json

- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: vulnerability-report
    path: vulnerability-report.json
```

## FAQ

<details>
<summary><strong>What is the <code>allDeps</code> task?</strong></summary>

It's a custom Gradle task of type `DependencyReportTask` that prints the dependency tree for all subprojects. Register it in your root build file to enable multi-module scanning.
</details>

<details>
<summary><strong>Does it support Kotlin DSL (<code>.kts</code>)?</strong></summary>

Yes. Gradle Guard detects both Groovy and Kotlin DSL build files. The dependency resolution relies on the Gradle wrapper, which works identically for both.
</details>

<details>
<summary><strong>Does it need internet access?</strong></summary>

Yes. Gradle Guard queries the [OSV.dev](https://osv.dev/) public API to check for vulnerabilities. No API key is required.
</details>

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ❤️ for secure Java ecosystems
</p>
