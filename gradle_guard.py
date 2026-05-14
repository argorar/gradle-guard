#!/usr/bin/env python3
"""
Gradle Dependency Vulnerability Scanner
========================================
Scans a Java Gradle project's dependencies, including multi-module when using
an allDeps Gradle task, and checks for known vulnerabilities using the OSV API.

Usage Windows:
    python gradle_guard.py C:\\path\\to\\gradle\\project

Usage Mac/Linux:
    python gradle_guard.py ~/Downloads/my-project

Export report:
    python gradle_guard.py ~/Downloads/my-project --json report.json

Recommended Gradle task for multi-module projects:

Add this to the root main.gradle:

    allprojects {
        tasks.register("allDeps", DependencyReportTask) {}
    }

Then this script will run:

    ./gradlew allDeps -q --no-daemon
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
except ImportError:
    print("❌ 'requests' required: pip install requests")
    sys.exit(1)


# ─── ANSI Colors ────────────────────────────────────────────────────────────────

class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    CN = "\033[96m"
    W = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RST = "\033[0m"


# ─── Data Models ────────────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    vuln_id: str
    aliases: list
    summary: str
    severity: str
    fixed_versions: list
    references: list


@dataclass
class Dependency:
    group: str
    artifact: str
    version: str
    source_file: str = ""
    vulnerabilities: list = field(default_factory=list)

    @property
    def coordinate(self):
        return f"{self.group}:{self.artifact}"

    @property
    def full_coordinate(self):
        return f"{self.group}:{self.artifact}:{self.version}"


# ─── Gradle Variable Resolution ────────────────────────────────────────────────


def resolve_version(version_str: str, variables: dict) -> Optional[str]:
    if not version_str:
        return None

    resolved = version_str

    # Handle ${varName}
    for m in re.finditer(r"\$\{(\w+)}", version_str):
        val = variables.get(m.group(1))
        if val:
            resolved = resolved.replace(m.group(0), val)

    # Handle $varName
    for m in re.finditer(r"\$(\w+)", resolved):
        val = variables.get(m.group(1))
        if val:
            resolved = resolved.replace(m.group(0), val)

    if "$" in resolved:
        return None

    return resolved


# ─── Dependency Extraction ──────────────────────────────────────────────────────

def find_all_build_files(project_path: str) -> list:
    result = []

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [
            d for d in dirs
            if d not in {".gradle", "build", ".git", "node_modules"}
        ]

        for f in files:
            if f in ("build.gradle", "build.gradle.kts", "main.gradle"):
                result.append(os.path.join(root, f))

    return result


def try_gradle_dependencies(project_path: str) -> list:
    is_windows = os.name == "nt"

    gradlew_unix = os.path.join(project_path, "gradlew")
    gradlew_win = os.path.join(project_path, "gradlew.bat")

    if is_windows and os.path.isfile(gradlew_win):
        cmd = gradlew_win
    elif not is_windows and os.path.isfile(gradlew_unix):
        cmd = gradlew_unix
        os.chmod(gradlew_unix, 0o755)
    else:
        cmd = "gradle"

    dep_pattern = re.compile(
        r"(?:[|\\+`\-\s]+)?"
        r"([A-Za-z0-9_.\-]+):"
        r"([A-Za-z0-9_.\-]+):"
        r"([A-Za-z0-9_.+\-]+)"
        r"(?:\s*->\s*([A-Za-z0-9_.+\-]+))?"
    )

    print(f"{C.DIM}   Running command: {cmd} allDeps -q --no-daemon{C.RST}")

    try:
        result = subprocess.run(
            [cmd, "allDeps", "-q", "--no-daemon"],
            capture_output=True,
            text=True,
            cwd=project_path,
            timeout=180,
            shell=False
        )

        deps = {}
        for line in result.stdout.splitlines():
            m = dep_pattern.search(line)
            if m:
                g, a = m.group(1), m.group(2)
                v = m.group(4) or m.group(3)
                key = f"{g}:{a}:{v}"
                if key not in deps:
                    deps[key] = Dependency(
                        group=g,
                        artifact=a,
                        version=v,
                        source_file="gradle-resolved"
                    )

        return list(deps.values())

    except Exception as e:
        print(f"{C.Y}   ⚠ Gradle execution failed: {e}{C.RST}")
        print("Make sure allDeps is in your main.gradle")
        return []


def get_dependencies(project_path: str) -> list:
    print(f"\n{C.CN}{C.BOLD}📦 Scanning: {project_path}{C.RST}")

    print(f"{C.DIM}   Trying Gradle dependencies task...{C.RST}")
    deps = try_gradle_dependencies(project_path)

    resolved = [d for d in deps if d.version != "MANAGED"]
    managed = [d for d in deps if d.version == "MANAGED"]

    if resolved:
        print(f"{C.G}   ✅ {len(resolved)} dependencies with known versions{C.RST}")

    if managed:
        print(
            f"{C.Y}   ⚠ {len(managed)} dependencies with BOM-managed versions "
            f"(skipped){C.RST}"
        )
        for d in managed:
            print(f"{C.DIM}      - {d.coordinate} ({d.source_file}){C.RST}")

    if not resolved:
        print(f"{C.R}   ❌ No dependencies found with resolvable versions.{C.RST}")

    return resolved


# ─── OSV Vulnerability Queries ──────────────────────────────────────────────────

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
BATCH_SIZE = 50


def query_osv_batch(deps: list) -> dict:
    results = {}

    for i in range(0, len(deps), BATCH_SIZE):
        batch = deps[i:i + BATCH_SIZE]

        queries = [
            {
                "package": {
                    "name": d.coordinate,
                    "ecosystem": "Maven",
                },
                "version": d.version,
            }
            for d in batch
        ]

        try:
            resp = requests.post(
                OSV_BATCH_URL,
                json={"queries": queries},
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()

            for idx, r in enumerate(resp.json().get("results", [])):
                vulns = r.get("vulns", [])

                if vulns:
                    results[batch[idx].full_coordinate] = vulns

        except requests.exceptions.RequestException as e:
            print(f"{C.Y}   ⚠ API error: {e}{C.RST}")
            print(f"{C.DIM}   Falling back to individual OSV queries...{C.RST}")

            for d in batch:
                try:
                    r2 = requests.post(
                        OSV_QUERY_URL,
                        json={
                            "package": {
                                "name": d.coordinate,
                                "ecosystem": "Maven",
                            },
                            "version": d.version,
                        },
                        timeout=15,
                    )

                    if r2.status_code == 200:
                        vulns = r2.json().get("vulns", [])

                        if vulns:
                            results[d.full_coordinate] = vulns

                except Exception:
                    pass

        if i + BATCH_SIZE < len(deps):
            time.sleep(0.3)

    return results


def extract_fixed_versions(vuln_data: dict, pkg_name: str) -> list:
    """
    Extract all fixed versions reported by OSV for a Maven package.

    Some libraries, like Spring, may have multiple supported release lines with
    different fixed versions, for example:
      - 3.5.14
      - 4.0.6
    """
    fixed_versions = []

    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})

        if pkg.get("name") == pkg_name and pkg.get("ecosystem") == "Maven":
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")

                    if fixed and fixed not in fixed_versions:
                        fixed_versions.append(fixed)

    return fixed_versions


def extract_severity(vuln_data: dict) -> str:
    db = vuln_data.get("database_specific", {})

    if db.get("severity"):
        return str(db["severity"]).upper()

    for affected in vuln_data.get("affected", []):
        ecosystem_specific = affected.get("ecosystem_specific", {})

        if ecosystem_specific.get("severity"):
            return str(ecosystem_specific["severity"]).upper()

    for s in vuln_data.get("severity", []):
        score_str = s.get("score", "")

        if "CVSS" in score_str:
            return "HIGH"

    return "UNKNOWN"


def fetch_vuln_detail(vuln_id: str) -> Optional[dict]:
    if not vuln_id:
        return None

    try:
        resp = requests.get(
            f"https://api.osv.dev/v1/vulns/{vuln_id}",
            timeout=15,
        )

        if resp.status_code == 200:
            return resp.json()

    except Exception:
        pass

    return None


def parse_vulns(vuln_list: list, pkg_name: str) -> list:
    parsed = []

    for v in vuln_list:
        if not v.get("summary") and not v.get("details"):
            detail = fetch_vuln_detail(v.get("id", ""))

            if detail:
                v = detail

        aliases = v.get("aliases", [])
        refs = [
            r["url"]
            for r in v.get("references", [])
            if r.get("url")
        ][:3]

        summary = v.get("summary", "")

        if not summary:
            details = v.get("details", "No description")
            summary = details[:200] if details else "No description"

        parsed.append(
            Vulnerability(
                vuln_id=v.get("id", "N/A"),
                aliases=aliases,
                summary=summary,
                severity=extract_severity(v),
                fixed_versions=extract_fixed_versions(v, pkg_name),
                references=refs,
            )
        )

        time.sleep(0.1)

    return parsed


# ─── Report ─────────────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": C.R + C.BOLD,
    "HIGH": C.R,
    "MEDIUM": C.Y,
    "LOW": C.B,
    "UNKNOWN": C.DIM,
}

SEV_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}


def print_report(deps: list):
    affected = [d for d in deps if d.vulnerabilities]
    total_vulns = sum(len(d.vulnerabilities) for d in affected)

    print(f"\n{'═' * 80}")
    print(f"{C.BOLD}  🛡️  VULNERABILITY SCAN REPORT{C.RST}")
    print(f"{'═' * 80}")
    print(f"  Scanned                  : {C.BOLD}{len(deps)}{C.RST}")
    print(f"  Vulnerable dependencies  : {C.R}{C.BOLD}{len(affected)}{C.RST}")
    print(f"  Vulns                    : {C.R}{C.BOLD}{total_vulns}{C.RST}")
    print(f"{'═' * 80}\n")

    if not affected:
        print(f"  {C.G}{C.BOLD}✅ No vulnerabilities found!{C.RST}\n")
        return

    affected.sort(
        key=lambda d: min(
            SEV_ORDER.get(v.severity, 5)
            for v in d.vulnerabilities
        )
    )

    for dep in affected:
        print(f"  {C.BOLD}{C.W}📦 {dep.full_coordinate}{C.RST}")

        if dep.source_file:
            print(f"     {C.DIM}Source: {dep.source_file}{C.RST}")

        dep.vulnerabilities.sort(
            key=lambda v: SEV_ORDER.get(v.severity, 5)
        )

        for vuln in dep.vulnerabilities:
            sc = SEV_COLOR.get(vuln.severity, C.DIM)
            cves = [a for a in vuln.aliases if a.startswith("CVE-")]
            cve_str = f" ({', '.join(cves)})" if cves else ""

            print(
                f"\n     {sc}[{vuln.severity}]{C.RST} "
                f"{C.BOLD}{vuln.vuln_id}{C.RST}{cve_str}"
            )
            print(f"     {C.DIM}{vuln.summary[:120]}{C.RST}")

            if vuln.fixed_versions:
                print(
                    f"     {C.G}✅ Upgrade alternatives: "
                    f"{C.BOLD}{', '.join(vuln.fixed_versions)}{C.RST}"
                )
            else:
                print(f"     {C.Y}⚠  No fix version available{C.RST}")

            for ref in vuln.references:
                print(f"     {C.DIM}  • {ref}{C.RST}")

        print(f"\n  {'─' * 76}\n")

    # Upgrade summary table
    upgrades = {}

    for dep in affected:
        for vuln in dep.vulnerabilities:
            if vuln.fixed_versions:
                key = dep.coordinate

                if key not in upgrades:
                    upgrades[key] = {
                        "current": dep.version,
                        "fixed_versions": set(),
                        "vulns": set(),
                    }

                upgrades[key]["fixed_versions"].update(vuln.fixed_versions)
                upgrades[key]["vulns"].add(vuln.vuln_id)

    if upgrades:
        print(f"\n{C.BOLD}{C.CN}  📋 RECOMMENDED UPGRADES{C.RST}")
        print(f"  {'─' * 120}")
        print(
            f"  {'Library':<45} "
            f"{'Current':<14} "
            f"{'Upgrade Alternatives':<40} "
        )
        print(f"  {'─' * 120}")

        for lib, info in sorted(upgrades.items()):
            current = info["current"]
            fixed_versions = sorted(info["fixed_versions"])

            alternatives = ", ".join(fixed_versions)

            print(
                f"  {lib:<45} "
                f"{C.R}{current:<14}{C.RST} "
                f"{C.G}{C.BOLD}{alternatives:<40}{C.RST} "
            )

        print(f"  {'─' * 120}\n")


def export_json(deps: list, path: str):
    affected = [d for d in deps if d.vulnerabilities]

    report = {
        "scan_date": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "total": len(deps),
        "vulnerable": len(affected),
        "results": [
            {
                "coordinate": d.full_coordinate,
                "vulnerabilities": [
                    {
                        "id": v.vuln_id,
                        "aliases": v.aliases,
                        "severity": v.severity,
                        "summary": v.summary,
                        "fixed_versions": v.fixed_versions,
                    }
                    for v in d.vulnerabilities
                ],
            }
            for d in affected
        ],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"  {C.CN}📄 JSON report: {path}{C.RST}")


# ─── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scan Gradle dependencies for vulnerabilities."
    )
    parser.add_argument(
        "project_path",
        help="Path to Gradle project root.",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Export JSON report.",
    )

    args = parser.parse_args()

    project_path = os.path.abspath(os.path.expanduser(args.project_path))

    if not os.path.isdir(project_path):
        print(f"{C.R}❌ Directory not found: {project_path}{C.RST}")
        sys.exit(1)

    has_build = any(
        os.path.isfile(os.path.join(project_path, f))
        for f in [
            "build.gradle",
            "build.gradle.kts",
            "main.gradle",
            "settings.gradle",
            "settings.gradle.kts",
        ]
    )

    if not has_build:
        print(f"{C.R}❌ No Gradle build files in: {project_path}{C.RST}")
        sys.exit(1)

    deps = get_dependencies(project_path)

    if not deps:
        sys.exit(1)

    print(f"\n{C.CN}{C.BOLD}🔍 Querying OSV API...{C.RST}")
    vuln_results = query_osv_batch(deps)

    for dep in deps:
        raw = vuln_results.get(dep.full_coordinate, [])

        if raw:
            dep.vulnerabilities = parse_vulns(raw, dep.coordinate)

    vc = sum(1 for d in deps if d.vulnerabilities)
    print(f"{C.G}   ✅ Done. {vc} vulnerable dependencies.{C.RST}")

    print_report(deps)

    if args.json:
        export_json(deps, args.json)


if __name__ == "__main__":
    main()