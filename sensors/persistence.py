"""
GUARDIAN Persistence Detector
Scans Python packages/repos for hidden persistence mechanisms.
Adapted from Lazarus persistence_detector.py.
"""

import os
import re
import ast
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Finding:
    file: str
    line: int
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    pattern: str
    context: str
    explanation: str


@dataclass
class ScanResult:
    path: str
    total_files: int
    total_findings: int
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)


# Each pattern: (regex, category, severity, explanation)
PATTERNS = [
    # === CRITICAL: Direct persistence mechanisms ===
    (r'gc\.callbacks\s*\.\s*append', "gc_callback", "CRITICAL",
     "Registers a garbage collector callback. Code executes on every GC cycle, survives unimporting."),
    (r'gc\.callbacks\s*\.\s*(?:insert|extend|\+=)', "gc_callback", "CRITICAL",
     "Modifies gc.callbacks list. Persistence through garbage collector."),
    (r'gc\.set_threshold', "gc_manipulation", "HIGH",
     "Changes GC threshold. Can force more frequent GC cycles or disable GC."),
    (r'atexit\.register', "atexit_hook", "HIGH",
     "Registers shutdown handler. Code runs when Python exits."),
    (r'sys\.meta_path\s*\.\s*(?:append|insert)', "import_hook", "CRITICAL",
     "Installs an import hook. Can intercept ALL future imports and inject code."),
    (r'sys\.path_hooks\s*\.\s*(?:append|insert)', "import_hook", "CRITICAL",
     "Installs a path hook on the import system."),
    (r'sys\.settrace\s*\(', "trace_hook", "CRITICAL",
     "Sets a trace function. Code executes on EVERY line in the entire program."),
    (r'sys\.setprofile\s*\(', "profile_hook", "HIGH",
     "Sets a profile function. Code executes on every call/return."),
    (r'builtins\.__import__\s*=', "import_override", "CRITICAL",
     "Overrides the __import__ builtin. ALL future imports go through attacker code."),
    (r'__builtins__\s*\[.*__import__.*\]\s*=', "import_override", "CRITICAL",
     "Overrides __import__ via __builtins__ dict."),

    # === HIGH: Stealth execution ===
    (r'signal\.signal\s*\(', "signal_handler", "HIGH",
     "Registers a signal handler. Persists for process lifetime."),
    (r'threading\.Thread\s*\(', "thread_spawn", "HIGH",
     "Spawns a thread. If at import time, background persistence."),
    (r'(?:subprocess|os)\s*\.\s*(?:Popen|system|exec|spawn)', "subprocess_spawn", "CRITICAL",
     "Spawns a subprocess. If at import time, immediate code execution outside Python."),
    (r'os\.fork\s*\(', "process_fork", "CRITICAL",
     "Forks the process. Creates a persistent child process."),
    (r'(?:exec|eval)\s*\(\s*(?:base64|codecs|zlib|gzip|bz2|lzma)', "obfuscated_exec", "CRITICAL",
     "Executes decoded/decompressed code. Classic malware pattern."),
    (r'exec\s*\(\s*(?:compile|bytes|bytearray)', "obfuscated_exec", "CRITICAL",
     "Executes compiled/byte code. Hides payload from static analysis."),
    (r'(?:base64\.b64decode|codecs\.decode)\s*\(.*\)\s*\)\s*$', "obfuscated_exec", "HIGH",
     "Decodes obfuscated data. Check if the result is executed."),
    (r'compile\s*\(.*["\']exec["\']\s*\)', "dynamic_compile", "HIGH",
     "Compiles code dynamically with exec mode."),

    # === HIGH: Network activity on import ===
    (r'(?:urllib|requests|http\.client|httpx|aiohttp)\s*\.\s*(?:get|post|put|request|urlopen|Request)',
     "network_import", "HIGH",
     "HTTP request. If at import time, immediate phone-home."),
    (r'socket\.socket\s*\(', "raw_socket", "HIGH",
     "Creates a raw socket. Could be reverse shell or data exfil."),
    (r'socket\.connect\s*\(', "socket_connect", "HIGH",
     "Connects a socket. Outbound network connection."),

    # === HIGH: Native code loading ===
    (r'ctypes\.(?:CDLL|cdll|WinDLL|windll|OleDLL|oledll|LibraryLoader)', "native_load", "HIGH",
     "Loads a native library via ctypes. Bypasses Python sandbox."),
    (r'cffi\.FFI\(\)', "native_load", "HIGH",
     "Creates CFFI interface. Native code execution."),
    (r'ctypes\.cast|ctypes\.memmove|ctypes\.memset', "memory_manipulation", "HIGH",
     "Direct memory manipulation via ctypes."),

    # === MEDIUM: File system operations at import time ===
    (r'(?:open|Path)\s*\(.*["\'](?:/etc/|/tmp/|/var/|~|\.ssh|\.bashrc|\.profile|\.env|\.aws|\.kube)',
     "sensitive_file_access", "HIGH",
     "Accesses sensitive file path. Could be reading credentials."),
    (r'os\.environ\s*\[', "env_read", "MEDIUM",
     "Reads environment variable. Could be harvesting API keys."),
    (r'os\.(?:chmod|chown|symlink|link|rename|remove|unlink|rmdir|makedirs)\s*\(',
     "filesystem_modify", "MEDIUM",
     "Modifies filesystem. If at import time, could be dropping payloads."),

    # === MEDIUM: Suspicious patterns ===
    (r'__del__\s*\(\s*self\s*\)', "destructor", "MEDIUM",
     "Defines __del__ (destructor). Code runs during garbage collection."),
    (r'weakref\.finalize', "weak_finalizer", "MEDIUM",
     "Registers a weak reference finalizer. Runs when object is collected."),
    (r'importlib\.(?:import_module|__import__|reload)', "dynamic_import", "MEDIUM",
     "Dynamic import. Could be loading a payload module at runtime."),
    (r'(?:pickle|marshal|shelve)\.(?:load|loads)\s*\(', "deserialization", "HIGH",
     "Deserializes data. pickle.loads() is arbitrary code execution."),
    (r'yaml\.(?:load|unsafe_load)\s*\(', "yaml_deserialize", "HIGH",
     "YAML deserialization without SafeLoader allows arbitrary code execution."),
]


def scan_file(filepath: str, patterns: list = None) -> list:
    """Scan a single Python file for persistence patterns."""
    if patterns is None:
        patterns = PATTERNS
    findings = []
    try:
        content = Path(filepath).read_text(errors="ignore")
        lines = content.splitlines()
    except Exception:
        return []

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for regex, category, severity, explanation in patterns:
            if re.search(regex, stripped):
                findings.append(Finding(
                    file=filepath, line=line_num, category=category,
                    severity=severity, pattern=regex[:60],
                    context=stripped[:200], explanation=explanation,
                ))
    return findings


def check_init_time_execution(filepath: str) -> list:
    """AST-based check: is code at module level (executes on import)?"""
    findings = []
    try:
        content = Path(filepath).read_text(errors="ignore")
        tree = ast.parse(content)
    except Exception:
        return []

    dangerous_names = {
        "gc", "atexit", "signal", "sys", "ctypes", "subprocess",
        "os", "socket", "threading", "multiprocessing",
        "urllib", "requests", "http", "httpx",
    }

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Attribute):
                if isinstance(call.func.value, ast.Name):
                    module = call.func.value.id
                    method = call.func.attr
                    call_name = f"{module}.{method}"
                    if module in dangerous_names:
                        findings.append(Finding(
                            file=filepath, line=node.lineno,
                            category="import_time_call", severity="HIGH",
                            pattern=f"top-level: {call_name}()",
                            context=ast.get_source_segment(content, node) or call_name,
                            explanation=f"Calls {call_name}() at module level. Executes immediately on import."
                        ))
            elif isinstance(call.func, ast.Name):
                if call.func.id in ("exec", "eval", "compile", "__import__"):
                    findings.append(Finding(
                        file=filepath, line=node.lineno,
                        category="import_time_exec", severity="CRITICAL",
                        pattern=f"top-level: {call.func.id}()",
                        context=ast.get_source_segment(content, node) or call.func.id,
                        explanation=f"Calls {call.func.id}() at module level. Almost certainly malicious in a library."
                    ))
    return findings


def scan_package(path: str, deep: bool = False) -> ScanResult:
    """Scan a Python package or repo for persistence mechanisms."""
    root = Path(path)
    result = ScanResult(path=path, total_files=0, total_findings=0)

    py_files = []
    for f in root.rglob("*.py"):
        fstr = str(f)
        if not deep:
            if any(skip in fstr for skip in [
                "/venv/", "/env/", "/.venv/", "/site-packages/",
                "/node_modules/", "/__pycache__/", "/.git/",
                "/dist/", "/build/", "/.eggs/",
            ]):
                continue
        py_files.append(str(f))

    result.total_files = len(py_files)
    category_counts = {}

    for filepath in py_files:
        findings = scan_file(filepath, PATTERNS)
        ast_findings = check_init_time_execution(filepath)
        findings.extend(ast_findings)

        for f in findings:
            if "__init__.py" in filepath:
                if f.severity == "MEDIUM":
                    f.severity = "HIGH"
                elif f.severity == "HIGH":
                    f.severity = "CRITICAL"
                f.explanation += " [IN __init__.py - RUNS ON IMPORT]"

        if findings:
            for f in findings:
                category_counts[f.category] = category_counts.get(f.category, 0) + 1

        result.findings.extend(findings)

    result.total_findings = len(result.findings)
    result.summary = category_counts
    return result


def scan_downloaded_package(package_name: str, temp_dir: str = "/tmp/guardian_scan") -> ScanResult:
    """Download a PyPI package and scan it without installing."""
    import subprocess
    import tarfile
    import zipfile

    pkg_dir = Path(temp_dir) / package_name
    pkg_dir.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            ["pip", "download", "--no-deps", "--no-binary", ":all:",
             "-d", str(pkg_dir), package_name],
            capture_output=True, text=True, timeout=30
        )
    except Exception:
        try:
            subprocess.run(
                ["pip", "download", "--no-deps",
                 "-d", str(pkg_dir), package_name],
                capture_output=True, text=True, timeout=30
            )
        except Exception:
            return ScanResult(path=str(pkg_dir), total_files=0, total_findings=0)

    extract_dir = pkg_dir / "extracted"
    extract_dir.mkdir(exist_ok=True)

    for archive in pkg_dir.iterdir():
        if archive.suffix == ".gz" or archive.name.endswith(".tar.gz"):
            try:
                with tarfile.open(archive) as tar:
                    tar.extractall(path=extract_dir, filter="data")
            except Exception:
                pass
        elif archive.suffix == ".whl" or archive.suffix == ".zip":
            try:
                with zipfile.ZipFile(archive) as zf:
                    zf.extractall(path=extract_dir)
            except Exception:
                pass

    return scan_package(str(extract_dir))


def format_results(result: ScanResult, verbose: bool = True) -> str:
    """Format scan results for display."""
    lines = []
    lines.append(f"  Scanned {result.total_files} Python files in {result.path}")
    lines.append(f"  Total findings: {result.total_findings}")

    if verbose and result.findings:
        for f in result.findings:
            sev_marker = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  ", "LOW": "   "}
            lines.append(f"    {sev_marker.get(f.severity, '   ')} [{f.severity:8s}] {f.file}:{f.line} {f.category}")
            lines.append(f"         {f.context[:100]}")

    if result.summary:
        lines.append(f"\n  By category:")
        for cat, count in sorted(result.summary.items(), key=lambda x: -x[1]):
            lines.append(f"    {count:3d}  {cat}")

    severity_counts = {}
    for f in result.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    if severity_counts:
        lines.append(f"\n  By severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in severity_counts:
                lines.append(f"    {severity_counts[sev]:3d}  {sev}")

    return "\n".join(lines)
