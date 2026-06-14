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
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
import threading
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
except ImportError:
    print("❌ 'requests' required: pip install requests")
    sys.exit(1)


__version__ = "1.1.1"
GITHUB_REPO = "argorar/gradle-guard"


# ─── ANSI Colors ────────────────────────────────────────────────────────────────

class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    CN = "\033[96m"
    W = "\033[97m"
    O = "\033[38;5;208m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RST = "\033[0m"


# ─── Spinner System ─────────────────────────────────────────────────────────────

class Spinner:
    def __init__(self, message="Loading...", delay=0.1):
        self.message = message
        self.delay = delay
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self._running = False
        self._thread = None

    def spin(self):
        idx = 0
        while self._running:
            char = self.spinner_chars[idx % len(self.spinner_chars)]
            sys.stdout.write(f"\r {C.CN}{char}{C.RST} {self.message}")
            sys.stdout.flush()
            idx += 1
            time.sleep(self.delay)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self.spin, daemon=True)
        self._thread.start()

    def stop(self, success=True, custom_msg=None):
        self._running = False
        if self._thread:
            self._thread.join()
        sys.stdout.write("\r" + " " * (len(self.message) + 15) + "\r")
        sys.stdout.flush()
        if custom_msg:
            print(custom_msg)
        elif success:
            print(f" {C.G}✅{C.RST} {self.message}")
        else:
            print(f" {C.R}❌{C.RST} {self.message}")


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


@dataclass
class DependencyTreeNode:
    label: str
    dependency: Optional[Dependency] = None
    children: list = field(default_factory=list)


# ─── Cache System ─────────────────────────────────────────────────────────────

CACHE_PATH = os.path.expanduser("~/.gradle_guard_cache.json")
CACHE_TTL = 86400  # 24 hours in seconds
_cache = {"queries": {}, "details": {}}


def load_cache():
    global _cache
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                _cache = json.load(f)
            if "queries" not in _cache:
                _cache["queries"] = {}
            if "details" not in _cache:
                _cache["details"] = {}
        except Exception:
            _cache = {"queries": {}, "details": {}}


def save_cache():
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_cache, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def check_for_updates(force_update=False):
    """
    Checks GitHub for the latest release.
    If a new version is found (or if force_update is True), prompts the user
    to update and downloads/overwrites the current script.
    """
    print(f"{C.CN}🔄 Checking for updates...{C.RST}")
    url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 404:
            print(f"{C.Y}No releases found on GitHub for {GITHUB_REPO} yet.{C.RST}")
            return
        response.raise_for_status()
        data = response.json()
        latest_tag = data.get("tag_name", "")
        if not latest_tag:
            print(f"{C.Y}⚠ No release tags found on GitHub.{C.RST}")
            return

        latest_ver = latest_tag.lstrip("v")
        current_ver = __version__

        try:
            latest_parts = [int(x) for x in latest_ver.split(".")]
            current_parts = [int(x) for x in current_ver.split(".")]
            has_update = latest_parts > current_parts
        except ValueError:
            has_update = latest_ver != current_ver

        if not has_update and not force_update:
            print(f"{C.G} GradleGuard is up to date (v{__version__}).{C.RST}")
            return

        if force_update:
            print(f"{C.Y}Force update requested. Re-downloading v{latest_tag}...{C.RST}")
        else:
            print(f"\n{C.Y}✨ A new version is available: {C.BOLD}{latest_tag}{C.RST} (Current: v{__version__})")

        # Ask user confirmation
        confirm = input("Do you want to update now? [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Update cancelled.")
            return

        # Perform update
        raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{latest_tag}/gradle_guard.py"
        print(f"Downloading update from {raw_url}...")
        raw_response = requests.get(raw_url, timeout=15)
        raw_response.raise_for_status()

        script_path = os.path.abspath(__file__)
        print(f"Overwriting {script_path}...")
        
        # Write new content
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(raw_response.text)

        print(f"{C.G} Successfully updated to {latest_tag}! Please run the script again.{C.RST}")
        sys.exit(0)

    except Exception as e:
        print(f"{C.R}❌ Error checking/performing update: {e}{C.RST}")


# ─── CLI Utilities ─────────────────────────────────────────────────────────────

def print_progress(current: int, total: int, prefix: str = "", suffix: str = ""):
    if total <= 0:
        return
    percent = int(100 * (current / total))
    filled_length = int(30 * current // total)
    bar = "█" * filled_length + "░" * (30 - filled_length)
    sys.stdout.write(f"\r{prefix} |{bar}| {percent}% {suffix}")
    sys.stdout.flush()
    if current == total:
        sys.stdout.write("\n")
        sys.stdout.flush()

def parse_gradle_dependency_output(output: str) -> tuple:
    dep_pattern = re.compile(
        r"(?:[|\\+`\-\s]+)?"
        r"([A-Za-z0-9_.\-]+):"
        r"([A-Za-z0-9_.\-]+):"
        r"([A-Za-z0-9_.+\-]+)"
        r"(?:\s*->\s*([A-Za-z0-9_.+\-]+))?"
    )
    tree_pattern = re.compile(r"^([| ]*)(?:\\---|\+---)\s+(.+)$")
    configuration_pattern = re.compile(r"^([A-Za-z][A-Za-z0-9_.-]*)\s+-\s+(.+)$")

    deps = {}
    tree_roots = []
    current_config = None
    stack = []

    for line in output.splitlines():
        config_match = configuration_pattern.match(line)
        if config_match:
            current_config = DependencyTreeNode(
                label=config_match.group(1),
                children=[],
            )
            stack = []
            continue

        tree_match = tree_pattern.match(line)
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

            if tree_match:
                if current_config is None:
                    current_config = DependencyTreeNode(
                        label="dependencies",
                        children=[],
                    )

                if current_config not in tree_roots:
                    tree_roots.append(current_config)

                level = len(tree_match.group(1)) // 5
                node = DependencyTreeNode(
                    label=deps[key].full_coordinate,
                    dependency=deps[key],
                )

                if level == 0:
                    current_config.children.append(node)
                else:
                    parent = stack[level - 1] if level - 1 < len(stack) else None
                    if parent:
                        parent.children.append(node)
                    else:
                        current_config.children.append(node)

                if level < len(stack):
                    stack[level] = node
                else:
                    stack.append(node)
                del stack[level + 1:]

    return list(deps.values()), tree_roots


def try_gradle_dependencies(project_path: str) -> tuple:
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

    spinner = Spinner("Analyzing dependencies with Gradle...")
    spinner.start()

    try:
        result = subprocess.run(
            [cmd, "allDeps", "-q", "--no-daemon"],
            capture_output=True,
            text=True,
            cwd=project_path,
            timeout=180,
            shell=False
        )

        spinner.stop(success=(result.returncode == 0))
        return parse_gradle_dependency_output(result.stdout)

    except Exception as e:
        spinner.stop(success=False)
        print(f"{C.Y}   ⚠ Gradle execution failed: {e}{C.RST}")
        print("Make sure allDeps is in your main.gradle")
        return [], []


def get_dependencies(project_path: str) -> tuple:
    print(f"\n{C.CN}{C.BOLD} Scanning: {project_path}{C.RST}")

    print(f"{C.DIM}   Trying Gradle dependencies task...{C.RST}")
    deps, tree_roots = try_gradle_dependencies(project_path)

    resolved = [d for d in deps if d.version != "MANAGED"]
    managed = [d for d in deps if d.version == "MANAGED"]

    if resolved:
        print(f"{C.G}    {len(resolved)} dependencies resolved{C.RST}")

    if managed:
        print(
            f"{C.Y}   ⚠ {len(managed)} dependencies with BOM-managed versions "
            f"(skipped){C.RST}"
        )
        for d in managed:
            print(f"{C.DIM}      - {d.coordinate} ({d.source_file}){C.RST}")

    if not resolved:
        print(f"{C.R}   ❌ No dependencies found with resolvable versions.{C.RST}")

    return resolved, tree_roots


# ─── OSV Vulnerability Queries ──────────────────────────────────────────────────

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
BATCH_SIZE = 50


def query_osv_batch(deps: list) -> dict:
    results = {}
    total = len(deps)
    now = time.time()

    for i in range(0, total, BATCH_SIZE):
        batch = deps[i:i + BATCH_SIZE]
        
        # Split batch into cache hits & API queries
        queries_to_send = []
        for d in batch:
            cache_key = d.full_coordinate
            if cache_key in _cache["queries"]:
                cache_entry = _cache["queries"][cache_key]
                if now - cache_entry.get("timestamp", 0) < CACHE_TTL:
                    vulns = cache_entry.get("vulns", [])
                    if vulns:
                        results[cache_key] = vulns
                    continue
            queries_to_send.append(d)

        if queries_to_send:
            queries = [
                {
                    "package": {
                        "name": d.coordinate,
                        "ecosystem": "Maven",
                    },
                    "version": d.version,
                }
                for d in queries_to_send
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
                    dep = queries_to_send[idx]
                    
                    # Update cache
                    _cache["queries"][dep.full_coordinate] = {
                        "timestamp": now,
                        "vulns": vulns
                    }

                    if vulns:
                        results[dep.full_coordinate] = vulns

            except requests.exceptions.RequestException as e:
                # Fallback to individual queries
                for d in queries_to_send:
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
                            _cache["queries"][d.full_coordinate] = {
                                "timestamp": now,
                                "vulns": vulns
                            }
                            if vulns:
                                results[d.full_coordinate] = vulns
                    except Exception:
                        pass

        progress_val = min(i + BATCH_SIZE, total)
        print_progress(progress_val, total, prefix=f"{C.DIM}   OSV Queries{C.RST}", suffix=f"Processed {progress_val}/{total}")

        if i + BATCH_SIZE < total and queries_to_send:
            time.sleep(0.3)

    return results


def extract_fixed_versions(vuln_data: dict, pkg_name: str) -> list:
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

    now = time.time()
    if vuln_id in _cache["details"]:
        cache_entry = _cache["details"][vuln_id]
        if now - cache_entry.get("timestamp", 0) < CACHE_TTL:
            return cache_entry.get("data")

    try:
        resp = requests.get(
            f"https://api.osv.dev/v1/vulns/{vuln_id}",
            timeout=15,
        )

        if resp.status_code == 200:
            data = resp.json()
            _cache["details"][vuln_id] = {
                "timestamp": now,
                "data": data
            }
            return data

    except Exception:
        pass

    return None


def parse_vulns(vuln_list: list, pkg_name: str) -> list:
    # Gather indexes that need full detail requests
    to_fetch = []
    for idx, v in enumerate(vuln_list):
        if not v.get("summary") and not v.get("details"):
            to_fetch.append((idx, v.get("id", "")))

    # Concurrently fetch detailed information using ThreadPoolExecutor
    if to_fetch:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_idx = {
                executor.submit(fetch_vuln_detail, vid): idx 
                for idx, vid in to_fetch
            }
            for future in concurrent.futures.as_completed(future_to_idx):
                idx = future_to_idx[future]
                detail = future.result()
                if detail:
                    vuln_list[idx] = detail

    parsed = []
    for v in vuln_list:
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

    return parsed





# ─── Report & Exporters ────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": C.R + C.BOLD,
    "HIGH": C.O + C.BOLD,
    "MEDIUM": C.Y,
    "MODERATE": C.Y,
    "LOW": C.B,
    "UNKNOWN": C.DIM,
}

SEV_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "MODERATE": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}


def natural_sort_key(s: str):
    return [int(x) if x.isdigit() else x.lower() for x in re.split(r'(\d+)', s)]


def display_severity(severity: str) -> str:
    severity = severity.upper()
    return "MEDIUM" if severity == "MODERATE" else severity


def tree_has_vulnerabilities(node: DependencyTreeNode) -> bool:
    if node.dependency and node.dependency.vulnerabilities:
        return True

    return any(tree_has_vulnerabilities(child) for child in node.children)


def tree_vulnerable_coordinates(node: DependencyTreeNode) -> set:
    coordinates = set()

    if node.dependency and node.dependency.vulnerabilities:
        coordinates.add(node.dependency.full_coordinate)

    for child in node.children:
        coordinates.update(tree_vulnerable_coordinates(child))

    return coordinates


def tree_signature(node: DependencyTreeNode):
    if node.dependency:
        label = node.dependency.full_coordinate
    else:
        label = "configuration"

    return (
        label,
        tuple(tree_signature(child) for child in node.children),
    )


def select_tree_roots(tree_roots: list, include_all: bool = False) -> list:
    if include_all:
        return tree_roots

    classpath_priority = {
        "runtimeClasspath": 0,
        "compileClasspath": 1,
        "testRuntimeClasspath": 2,
        "testCompileClasspath": 3,
    }
    classpath_roots = [
        root
        for root in tree_roots
        if root.children and root.label in classpath_priority
    ]
    roots_with_vulns = [
        root
        for root in classpath_roots
        if tree_has_vulnerabilities(root)
    ]
    selected = roots_with_vulns or classpath_roots

    covered_vulnerabilities = set()
    for root in selected:
        covered_vulnerabilities.update(tree_vulnerable_coordinates(root))

    for root in tree_roots:
        if not root.children or root in selected:
            continue

        vulnerable_coordinates = tree_vulnerable_coordinates(root)
        if vulnerable_coordinates - covered_vulnerabilities:
            selected.append(root)
            covered_vulnerabilities.update(vulnerable_coordinates)

    if not selected:
        selected = [root for root in tree_roots if root.children]

    selected.sort(
        key=lambda root: (
            classpath_priority.get(root.label, 99),
            root.label,
        )
    )

    deduped = []
    seen_signatures = set()
    for root in selected:
        signature = tree_signature(root)
        if signature in seen_signatures:
            continue

        seen_signatures.add(signature)
        deduped.append(root)

    return deduped


def print_vulnerability_tree(tree_roots: list, include_all: bool = False):
    print(f"\n{C.BOLD}{C.CN}  Gradle transitive dependency tree{C.RST}")

    visible_roots = select_tree_roots(tree_roots, include_all=include_all)

    if not visible_roots:
        print(f"  {C.Y}No Gradle dependency tree was captured.{C.RST}\n")
        return

    def vulnerability_badge(dep: Dependency) -> str:
        if not dep.vulnerabilities:
            return ""

        dep.vulnerabilities.sort(
            key=lambda v: (
                SEV_ORDER.get(v.severity.upper(), 5),
                v.vuln_id,
            )
        )
        worst_severity = display_severity(dep.vulnerabilities[0].severity)
        worst_color = SEV_COLOR.get(worst_severity, C.DIM)
        vuln_label = "vuln" if len(dep.vulnerabilities) == 1 else "vulns"
        return (
            f" {worst_color}[{worst_severity}]{C.RST}"
            f" {C.DIM}{len(dep.vulnerabilities)} {vuln_label}{C.RST}"
        )

    def print_node(node: DependencyTreeNode, prefix: str, is_last: bool):
        branch = "└──" if is_last else "├──"

        if node.dependency:
            dep = node.dependency
            color = C.BOLD + C.W if dep.vulnerabilities else C.W
            label = dep.full_coordinate
            suffix = vulnerability_badge(dep)
        else:
            color = C.BOLD + C.CN
            label = node.label
            suffix = ""

        print(f"  {C.W}{prefix}{branch}{C.RST} {color}{label}{C.RST}{suffix}")

        child_prefix = prefix + ("    " if is_last else "│   ")
        for child_index, child in enumerate(node.children):
            print_node(
                child,
                child_prefix,
                child_index == len(node.children) - 1,
            )

    for root_index, root in enumerate(visible_roots):
        print_node(root, "", root_index == len(visible_roots) - 1)

    print()


def print_report(deps: list, detailed: bool = False):
    affected = [d for d in deps if d.vulnerabilities]
    total_vulns = sum(len(d.vulnerabilities) for d in affected)

    # Calculate severity counts
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for d in affected:
        for v in d.vulnerabilities:
            s = v.severity.upper()
            if s == "MODERATE":
                s = "MEDIUM"
            if s in sev_counts:
                sev_counts[s] += 1
            else:
                sev_counts["UNKNOWN"] += 1

    box_width = 78
    title = "🛡️  GRADLE GUARD REPORT SUMMARY"
    padding_title = (box_width - len(title) - 2) // 2
    title_line = "│" + " " * padding_title + C.BOLD + C.CN + title + C.RST + " " * (box_width - padding_title - len(title) - 2) + "│"
    
    scan_raw = f"Scanned Dependencies : {len(deps)}"
    vuln_raw = f"Vulnerable Libraries : {len(affected)}"
    total_raw = f"Total vulnerabilities Found  : {total_vulns}"

    # with ANSI colors
    scan_line = f"Scanned Dependencies : {C.BOLD}{len(deps)}{C.RST}"
    vuln_line = f"Vulnerable Libraries : {C.R if affected else C.G}{C.BOLD}{len(affected)}{C.RST}"
    total_line = f"Total vulnerabilities Found  : {C.R if total_vulns else C.G}{C.BOLD}{total_vulns}{C.RST}"
    
    bd_raw = (
        f"CRITICAL: {sev_counts['CRITICAL']}   "
        f"HIGH: {sev_counts['HIGH']}   "
        f"MEDIUM: {sev_counts['MEDIUM']}   "
        f"LOW: {sev_counts['LOW']}   "
        f"UNKNOWN: {sev_counts['UNKNOWN']}"
    )
    bd_line = (
        f"{C.R}{C.BOLD}CRITICAL{C.RST}: {sev_counts['CRITICAL']}   "
        f"{C.O}{C.BOLD}HIGH{C.RST}: {sev_counts['HIGH']}   "
        f"{C.Y}{C.BOLD}MEDIUM{C.RST}: {sev_counts['MEDIUM']}   "
        f"{C.B}{C.BOLD}LOW{C.RST}: {sev_counts['LOW']}   "
        f"{C.DIM}UNKNOWN{C.RST}: {sev_counts['UNKNOWN']}"
    )

    print(f"\n{C.W}┌{'─' * (box_width - 2)}┐{C.RST}")
    print(title_line)
    print(f"{C.W}├{'─' * (box_width - 2)}┤{C.RST}")
    
    def print_box_row(content_str, raw_len):
        extra_len = box_width - 4 - raw_len
        print(f"{C.W}│{C.RST} {content_str}{' ' * extra_len} {C.W}│{C.RST}")

    severity = "Severity Breakdown:"
    print_box_row(scan_line, len(scan_raw))
    print_box_row(vuln_line, len(vuln_raw))
    print_box_row(total_line, len(total_raw))
    print_box_row("", 0)
    print_box_row(severity, len(severity))
    print_box_row(bd_line, len(bd_raw))
    print(f"{C.W}└{'─' * (box_width - 2)}┘{C.RST}\n")

    if not affected:
        print(f"  {C.G}{C.BOLD}✅ No vulnerabilities found!{C.RST}\n")
        return

    affected.sort(
        key=lambda d: min(
            SEV_ORDER.get(v.severity.upper(), 5)
            for v in d.vulnerabilities
        )
    )

    if detailed:
        for dep in affected:
            print(f"  {C.BOLD}{C.W}📦 {dep.full_coordinate}{C.RST}")

            if dep.source_file:
                print(f"     {C.DIM}Source: {dep.source_file}{C.RST}")

            dep.vulnerabilities.sort(
                key=lambda v: SEV_ORDER.get(v.severity.upper(), 5)
            )

            for vuln in dep.vulnerabilities:
                sc = SEV_COLOR.get(vuln.severity.upper(), C.DIM)
                cves = [a for a in vuln.aliases if a.startswith("CVE-")]
                cve_str = f" ({', '.join(cves)})" if cves else ""

                # Standardize Moderate to Medium for console output
                severity_label = display_severity(vuln.severity)

                print(
                    f"\n     {sc}[{severity_label}]{C.RST} "
                    f"{C.BOLD}{vuln.vuln_id}{C.RST}{cve_str}"
                )
                print(f"     {C.DIM}{vuln.summary[:120]}{C.RST}")

                if vuln.fixed_versions:
                    sorted_fixed = sorted(list(vuln.fixed_versions), key=natural_sort_key)
                    print(
                        f"     {C.G} Upgrade alternatives: "
                        f"{C.BOLD}{', '.join(sorted_fixed)}{C.RST}"
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
        
        # Calculate dynamic third column width based on the longest versions list
        max_alt_len = 20  # minimum width
        for lib, info in upgrades.items():
            fixed_versions = sorted(list(info["fixed_versions"]), key=natural_sort_key)
            alternatives_str = ", ".join(fixed_versions)
            if len(alternatives_str) > max_alt_len:
                max_alt_len = len(alternatives_str)
        col3_width = max_alt_len + 2

        # Table Header with box-drawing characters
        print(f"  ┌{'─' * 45}┬{'─' * 14}┬{'─' * col3_width}┐")
        print(
            f"  │ {'Library':<43} │ "
            f"{'Current':<12} │ "
            f"{'Upgrade Alternatives':<{col3_width - 2}} │"
        )
        print(f"  ├{'─' * 45}┼{'─' * 14}┼{'─' * col3_width}┤")

        for lib, info in sorted(upgrades.items()):
            current = info["current"]
            fixed_versions = sorted(list(info["fixed_versions"]), key=natural_sort_key)
            alternatives_str = ", ".join(fixed_versions)

            # Pad values safely BEFORE wrapping in ANSI codes
            lib_padded = f"{lib:<43}"
            current_padded = f"{current:<12}"
            alternatives_padded = f"{alternatives_str:<{col3_width - 2}}"

            print(
                f"  │ {C.W}{lib_padded}{C.RST} │ "
                f"{C.R}{current_padded}{C.RST} │ "
                f"{C.G}{C.BOLD}{alternatives_padded}{C.RST} │"
            )

        print(f"  └{'─' * 45}┴{'─' * 14}┴{'─' * col3_width}┘\n")


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
                        "severity": v.severity.upper() if v.severity.upper() != "MODERATE" else "MEDIUM",
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

    print(f"  {C.CN} JSON report: {path}{C.RST}")

# ─── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scan Gradle dependencies for vulnerabilities."
    )
    parser.add_argument(
        "project_path",
        nargs="?",
        help="Path to Gradle project root.",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Export JSON report.",
    )
    parser.add_argument(
        "--detailed", "-d",
        action="store_true",
        help="Print detailed vulnerability information for each package.",
    )
    parser.add_argument(
        "--tree",
        action="store_true",
        help="Print Gradle's transitive dependency tree and highlight vulnerable nodes.",
    )
    parser.add_argument(
        "--tree-all-configs",
        action="store_true",
        help="Print every Gradle configuration in the dependency tree.",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Check for updates and self-update the script.",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"GradleGuard v{__version__}",
    )
    args = parser.parse_args()

    # Load cache
    load_cache()

    if args.update:
        check_for_updates(force_update=True)
        sys.exit(0)

    if not args.project_path:
        parser.print_help()
        sys.exit(1)

    check_for_updates(force_update=False)

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

    deps, tree_roots = get_dependencies(project_path)

    if not deps:
        save_cache()
        sys.exit(1)

    print(f"\n{C.CN}{C.BOLD} Querying OSV API...{C.RST}")
    vuln_results = query_osv_batch(deps)

    for dep in deps:
        raw = vuln_results.get(dep.full_coordinate, [])
        if raw:
            dep.vulnerabilities = parse_vulns(raw, dep.coordinate)

    vc = sum(1 for d in deps if d.vulnerabilities)
    print(f"{C.G}    Done. {vc} vulnerable dependencies identified.{C.RST}")

    # Output Reports
    print_report(deps, detailed=args.detailed)

    if args.tree or args.tree_all_configs:
        print_vulnerability_tree(tree_roots, include_all=args.tree_all_configs)

    if args.json:
        export_json(deps, args.json)

    # Save Cache
    save_cache()


if __name__ == "__main__":
    main()
