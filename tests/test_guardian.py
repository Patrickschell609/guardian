"""
GUARDIAN Test Suite
Covers core modules without requiring API keys or network access.
Uses tmp_path for all file I/O and monkeypatch to block network calls.
"""

import sys
import os
import textwrap
from datetime import datetime, timedelta

import pytest

# ---------------------------------------------------------------------------
# Path setup so imports resolve from the project root's parent
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from guardian.sensors.persistence import scan_file, scan_package, Finding, ScanResult
from guardian.vault import init_vault, save_solution, get_best_prior, get_vault_stats
from guardian.analysis.graph import IntelGraph, Node, Edge
from guardian.analysis.patterns import PatternEngine, PatternConfig, PatternType
from guardian.analysis.entities import EntityResolver
from guardian.analysis.correlation import CrossSourceCorrelator
from guardian import config
from guardian.evaluator import format_evaluation


# ===================================================================
# 1. Persistence Scanner
# ===================================================================

class TestPersistenceScanner:
    """Tests for scan_file() and scan_package()."""

    def test_scan_file_detects_gc_callback(self, tmp_path):
        """scan_file should flag gc.callbacks.append as CRITICAL."""
        f = tmp_path / "evil.py"
        f.write_text("import gc\ngc.callbacks.append(lambda *a: None)\n")
        findings = scan_file(str(f))
        assert len(findings) >= 1
        cats = [fd.category for fd in findings]
        assert "gc_callback" in cats
        assert all(isinstance(fd, Finding) for fd in findings)
        gc_finding = next(fd for fd in findings if fd.category == "gc_callback")
        assert gc_finding.severity == "CRITICAL"

    def test_scan_file_detects_atexit(self, tmp_path):
        """scan_file should flag atexit.register."""
        f = tmp_path / "hook.py"
        f.write_text("import atexit\natexit.register(lambda: None)\n")
        findings = scan_file(str(f))
        cats = [fd.category for fd in findings]
        assert "atexit_hook" in cats

    def test_scan_file_detects_sys_settrace(self, tmp_path):
        """scan_file should flag sys.settrace as CRITICAL."""
        f = tmp_path / "trace.py"
        f.write_text("import sys\nsys.settrace(lambda *a: None)\n")
        findings = scan_file(str(f))
        cats = [fd.category for fd in findings]
        assert "trace_hook" in cats
        trace_finding = next(fd for fd in findings if fd.category == "trace_hook")
        assert trace_finding.severity == "CRITICAL"

    def test_scan_file_ignores_comments(self, tmp_path):
        """Lines that are comments should not produce findings."""
        f = tmp_path / "safe.py"
        f.write_text("# gc.callbacks.append(something)\n# sys.settrace(fn)\n")
        findings = scan_file(str(f))
        assert findings == []

    def test_scan_file_clean_file(self, tmp_path):
        """A normal Python file should produce zero findings."""
        f = tmp_path / "clean.py"
        f.write_text("def add(a, b):\n    return a + b\n")
        findings = scan_file(str(f))
        assert findings == []

    def test_scan_file_nonexistent_returns_empty(self, tmp_path):
        """scan_file on a missing file returns an empty list, not an error."""
        findings = scan_file(str(tmp_path / "does_not_exist.py"))
        assert findings == []

    def test_scan_package_with_malicious_file(self, tmp_path):
        """scan_package on a temp dir with a crafted malicious file."""
        pkg = tmp_path / "badpkg"
        pkg.mkdir()
        init_file = pkg / "__init__.py"
        init_file.write_text(textwrap.dedent("""\
            import gc
            import sys
            gc.callbacks.append(lambda *a: None)
            sys.meta_path.insert(0, object())
        """))
        result = scan_package(str(pkg))
        assert isinstance(result, ScanResult)
        assert result.total_files >= 1
        assert result.total_findings >= 2
        # Findings in __init__.py should be severity-escalated
        for fd in result.findings:
            assert fd.severity in ("HIGH", "CRITICAL")

    def test_scan_package_empty_dir(self, tmp_path):
        """scan_package on an empty dir returns zero findings."""
        empty = tmp_path / "empty"
        empty.mkdir()
        result = scan_package(str(empty))
        assert result.total_files == 0
        assert result.total_findings == 0

    def test_scan_package_skips_venv(self, tmp_path):
        """scan_package should skip files inside /venv/ by default."""
        pkg = tmp_path / "proj"
        venv = pkg / "venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "bad.py").write_text("gc.callbacks.append(None)\n")
        (pkg / "main.py").write_text("print('clean')\n")
        result = scan_package(str(pkg))
        # The venv file should be skipped
        scanned_files = [fd.file for fd in result.findings]
        assert not any("venv" in f for f in scanned_files)


# ===================================================================
# 2. Vault
# ===================================================================

class TestVault:
    """Tests for vault init, save, retrieve, and stats."""

    def test_vault_roundtrip(self, tmp_path, monkeypatch):
        """init_vault -> save_solution -> get_best_prior roundtrip."""
        db = str(tmp_path / "test_vault.db")
        monkeypatch.setattr("guardian.vault.DB_PATH", db)

        init_vault()

        problem = "How to detect gc persistence in Python packages?"
        solution = "Scan for gc.callbacks.append and related patterns."
        sid = save_solution(problem, solution, score=9, model_chain="claude->grok")
        assert isinstance(sid, int)
        assert sid > 0

        prior = get_best_prior(problem)
        assert prior is not None
        assert prior["solution"] == solution
        assert prior["score"] == 9
        assert prior["match_type"] == "exact"
        assert prior["model_chain"] == "claude->grok"

    def test_vault_no_prior_for_unknown(self, tmp_path, monkeypatch):
        """get_best_prior returns None for an unknown problem."""
        db = str(tmp_path / "empty_vault.db")
        monkeypatch.setattr("guardian.vault.DB_PATH", db)
        init_vault()
        result = get_best_prior("completely unrelated query xyz 12345")
        assert result is None

    def test_vault_stats(self, tmp_path, monkeypatch):
        """get_vault_stats returns correct counts after saving."""
        db = str(tmp_path / "stats_vault.db")
        monkeypatch.setattr("guardian.vault.DB_PATH", db)
        init_vault()

        stats = get_vault_stats()
        assert stats["total_solutions"] == 0
        assert stats["avg_score"] == 0
        assert stats["total_retrievals"] == 0

        save_solution("problem A", "solution A", score=8)
        save_solution("problem B", "solution B", score=6)

        stats = get_vault_stats()
        assert stats["total_solutions"] == 2
        assert stats["avg_score"] == 7.0

    def test_vault_save_higher_score_replaces(self, tmp_path, monkeypatch):
        """Saving a higher score for the same problem inserts a new row."""
        db = str(tmp_path / "replace_vault.db")
        monkeypatch.setattr("guardian.vault.DB_PATH", db)
        init_vault()

        sid1 = save_solution("problem X", "old answer", score=3)
        sid2 = save_solution("problem X", "better answer", score=9)

        # Different IDs since new row was inserted
        assert sid2 != sid1

        prior = get_best_prior("problem X")
        assert prior["score"] == 9
        assert prior["solution"] == "better answer"

    def test_vault_save_lower_score_keeps_existing(self, tmp_path, monkeypatch):
        """Saving a lower score for the same problem keeps existing."""
        db = str(tmp_path / "keep_vault.db")
        monkeypatch.setattr("guardian.vault.DB_PATH", db)
        init_vault()

        sid1 = save_solution("problem Y", "good answer", score=8)
        sid2 = save_solution("problem Y", "worse answer", score=3)

        # Should return the existing row's ID
        assert sid2 == sid1

        prior = get_best_prior("problem Y")
        assert prior["score"] == 8
        assert prior["solution"] == "good answer"


# ===================================================================
# 3. Intel Graph
# ===================================================================

class TestIntelGraph:
    """Tests for IntelGraph operations."""

    def _make_graph(self):
        g = IntelGraph()
        g.add_node(Node(id="a", node_type="actor", label="Alpha Group"))
        g.add_node(Node(id="b", node_type="actor", label="Beta Cell"))
        g.add_node(Node(id="c", node_type="location", label="Port City"))
        g.add_edge(Edge(id="e1", source_id="a", target_id="b", edge_type="allied_with"))
        g.add_edge(Edge(id="e2", source_id="b", target_id="c", edge_type="operates_in"))
        return g

    def test_add_node(self):
        g = IntelGraph()
        node = g.add_node(Node(id="x", node_type="actor", label="TestActor"))
        assert g.get_node("x") is not None
        assert g.get_node("x").label == "TestActor"

    def test_add_node_merges_duplicate(self):
        g = IntelGraph()
        g.add_node(Node(id="x", node_type="actor", label="A", source_ids=["s1"]))
        g.add_node(Node(id="x", node_type="actor", label="A", source_ids=["s2"],
                        properties={"key": "val"}))
        node = g.get_node("x")
        assert "s1" in node.source_ids
        assert "s2" in node.source_ids
        assert node.properties.get("key") == "val"

    def test_add_edge(self):
        g = self._make_graph()
        assert "e1" in g.edges
        assert "e2" in g.edges

    def test_add_edge_merges_duplicate(self):
        g = IntelGraph()
        g.add_node(Node(id="a", node_type="actor", label="A"))
        g.add_node(Node(id="b", node_type="actor", label="B"))
        g.add_edge(Edge(id="e1", source_id="a", target_id="b", edge_type="x", source_ids=["s1"]))
        g.add_edge(Edge(id="e1", source_id="a", target_id="b", edge_type="x", source_ids=["s2"]))
        edge = g.edges["e1"]
        assert "s1" in edge.source_ids
        assert "s2" in edge.source_ids
        assert edge.weight == 2.0  # incremented

    def test_get_neighbors(self):
        g = self._make_graph()
        # outgoing from b
        out = g.get_neighbors("b", direction="out")
        assert len(out) == 1
        assert out[0].id == "c"
        # incoming to b
        inc = g.get_neighbors("b", direction="in")
        assert len(inc) == 1
        assert inc[0].id == "a"
        # both
        both = g.get_neighbors("b", direction="both")
        ids = {n.id for n in both}
        assert ids == {"a", "c"}

    def test_find_path(self):
        g = self._make_graph()
        path = g.find_path("a", "c")
        assert path == ["a", "b", "c"]

    def test_find_path_no_connection(self):
        g = self._make_graph()
        g.add_node(Node(id="d", node_type="actor", label="Isolated"))
        path = g.find_path("a", "d")
        assert path is None

    def test_find_path_same_node(self):
        g = self._make_graph()
        path = g.find_path("a", "a")
        assert path == ["a"]

    def test_find_path_nonexistent_node(self):
        g = self._make_graph()
        path = g.find_path("a", "zzz")
        assert path is None

    def test_get_connected_component(self):
        g = self._make_graph()
        comp = g.get_connected_component("a")
        assert comp == {"a", "b", "c"}

    def test_get_connected_component_isolated(self):
        g = self._make_graph()
        g.add_node(Node(id="lone", node_type="actor", label="Lone Wolf"))
        comp = g.get_connected_component("lone")
        assert comp == {"lone"}

    def test_get_connected_component_nonexistent(self):
        g = IntelGraph()
        comp = g.get_connected_component("nope")
        assert comp == set()

    def test_get_stats(self):
        g = self._make_graph()
        stats = g.get_stats()
        assert stats["node_count"] == 3
        assert stats["edge_count"] == 2
        assert stats["node_types"]["actor"] == 2
        assert stats["node_types"]["location"] == 1
        assert stats["edge_types"]["allied_with"] == 1
        assert stats["edge_types"]["operates_in"] == 1


# ===================================================================
# 4. Pattern Engine
# ===================================================================

class TestPatternEngine:
    """Tests for PatternEngine.detect_all() with multi-source nodes."""

    def test_detect_all_recurring_entities(self):
        """Nodes appearing in multiple sources should trigger recurring_entity."""
        g = IntelGraph()
        # Create nodes that appear in multiple sources
        g.add_node(Node(id="e1", node_type="actor", label="Threat Actor X",
                        source_ids=["osint", "humint", "sigint"]))
        g.add_node(Node(id="e2", node_type="location", label="Port Alpha",
                        source_ids=["osint", "geoint"]))

        engine = PatternEngine(graph=g, config=PatternConfig(
            min_sources_for_pattern=2, min_confidence=0.3))
        patterns = engine.detect_all()
        assert len(patterns) >= 1

        recurring = [p for p in patterns if p.pattern_type == PatternType.RECURRING_ENTITY]
        assert len(recurring) >= 1
        # e1 has 3 sources so should definitely appear
        e1_patterns = [p for p in recurring if "e1" in p.entities]
        assert len(e1_patterns) >= 1
        assert len(e1_patterns[0].sources) == 3

    def test_detect_all_with_connected_network(self):
        """Connected nodes from multiple sources trigger shared_network."""
        g = IntelGraph()
        now = datetime.utcnow()
        g.add_node(Node(id="n1", node_type="actor", label="Actor A",
                        source_ids=["src_a"], first_seen=now))
        g.add_node(Node(id="n2", node_type="actor", label="Actor B",
                        source_ids=["src_b"], first_seen=now))
        g.add_node(Node(id="n3", node_type="location", label="Zone X",
                        source_ids=["src_a", "src_b"], first_seen=now))
        g.add_edge(Edge(id="e1", source_id="n1", target_id="n3", edge_type="operates_in"))
        g.add_edge(Edge(id="e2", source_id="n2", target_id="n3", edge_type="operates_in"))

        engine = PatternEngine(graph=g, config=PatternConfig(
            min_entities_for_pattern=2, min_sources_for_pattern=2, min_confidence=0.1))
        patterns = engine.detect_all()
        types = [p.pattern_type for p in patterns]
        assert PatternType.SHARED_NETWORK in types or PatternType.RECURRING_ENTITY in types

    def test_detect_all_empty_graph(self):
        """Empty graph should produce no patterns."""
        engine = PatternEngine(graph=IntelGraph())
        assert engine.detect_all() == []

    def test_detect_all_nodes_with_single_source(self):
        """Nodes with only one source should NOT trigger recurring_entity."""
        g = IntelGraph()
        g.add_node(Node(id="s1", node_type="actor", label="Solo", source_ids=["one"]))
        engine = PatternEngine(graph=g, config=PatternConfig(min_sources_for_pattern=2))
        patterns = engine.detect_all()
        recurring = [p for p in patterns if p.pattern_type == PatternType.RECURRING_ENTITY]
        assert len(recurring) == 0


# ===================================================================
# 5. Entity Resolver
# ===================================================================

class TestEntityResolver:
    """Tests for EntityResolver known alias resolution."""

    def test_resolve_houthi_ansar_allah(self):
        """'houthi' and 'ansar allah' should resolve to the same entity."""
        g = IntelGraph()
        g.add_node(Node(id="h1", node_type="group", label="Houthi",
                        source_ids=["osint"]))
        g.add_node(Node(id="h2", node_type="group", label="Ansar Allah",
                        source_ids=["humint"]))
        resolver = EntityResolver(graph=g, min_similarity=0.5)
        resolved = resolver.resolve_all()
        # Both should merge into a single resolved entity
        assert len(resolved) == 1
        re = resolved[0]
        assert len(re.source_node_ids) == 2
        assert "h1" in re.source_node_ids
        assert "h2" in re.source_node_ids
        # Canonical label should be title-cased known canonical
        assert re.canonical_label.lower() == "houthi"

    def test_resolve_hezbollah_aliases(self):
        """Multiple Hezbollah spellings should merge."""
        g = IntelGraph()
        g.add_node(Node(id="hz1", node_type="group", label="Hezbollah",
                        source_ids=["s1"]))
        g.add_node(Node(id="hz2", node_type="group", label="Hizbollah",
                        source_ids=["s2"]))
        resolver = EntityResolver(graph=g, min_similarity=0.5)
        resolved = resolver.resolve_all()
        assert len(resolved) == 1
        assert len(resolved[0].source_node_ids) == 2

    def test_resolve_different_entities_stay_separate(self):
        """Unrelated entities should not merge."""
        g = IntelGraph()
        g.add_node(Node(id="a1", node_type="group", label="Alpha Org",
                        source_ids=["s1"]))
        g.add_node(Node(id="b1", node_type="group", label="Zeta Corp",
                        source_ids=["s2"]))
        resolver = EntityResolver(graph=g, min_similarity=0.7)
        resolved = resolver.resolve_all()
        assert len(resolved) == 2

    def test_resolve_skips_thermal_events(self):
        """Nodes with type in SKIP_RESOLUTION_TYPES should be excluded."""
        g = IntelGraph()
        g.add_node(Node(id="t1", node_type="thermal_event", label="Fire A"))
        g.add_node(Node(id="t2", node_type="thermal_event", label="Fire A"))
        resolver = EntityResolver(graph=g)
        resolved = resolver.resolve_all()
        # thermal_event is skipped entirely
        assert len(resolved) == 0


# ===================================================================
# 6. Correlator
# ===================================================================

class TestCrossSourceCorrelator:
    """Tests for CrossSourceCorrelator temporal correlations."""

    def test_temporal_correlation(self):
        """Two nodes from different sources close in time should correlate."""
        g = IntelGraph()
        now = datetime.utcnow()
        g.add_node(Node(id="ev1", node_type="event", label="Explosion Alpha",
                        source_ids=["source_A"], first_seen=now))
        g.add_node(Node(id="ev2", node_type="event", label="Explosion Beta",
                        source_ids=["source_B"], first_seen=now + timedelta(hours=1)))
        correlator = CrossSourceCorrelator(
            graph=g, temporal_window_hours=24, min_strength=0.3)
        corrs = correlator.correlate_all()
        assert len(corrs) >= 1
        c = corrs[0]
        assert c.strength > 0.0
        assert c.event_a_id in ("ev1", "ev2")
        assert c.event_b_id in ("ev1", "ev2")

    def test_no_correlation_single_source(self):
        """Nodes from the same single source don't correlate cross-source."""
        g = IntelGraph()
        now = datetime.utcnow()
        g.add_node(Node(id="a", node_type="event", label="A",
                        source_ids=["same"], first_seen=now))
        g.add_node(Node(id="b", node_type="event", label="B",
                        source_ids=["same"], first_seen=now))
        correlator = CrossSourceCorrelator(graph=g)
        corrs = correlator.correlate_all()
        # Only one source, so no cross-source pairs
        assert len(corrs) == 0

    def test_no_correlation_far_apart(self):
        """Nodes far apart in time with high min_strength should not correlate."""
        g = IntelGraph()
        now = datetime.utcnow()
        g.add_node(Node(id="a", node_type="event", label="Event A",
                        source_ids=["src1"], first_seen=now))
        g.add_node(Node(id="b", node_type="event", label="Event B",
                        source_ids=["src2"], first_seen=now + timedelta(days=30)))
        correlator = CrossSourceCorrelator(
            graph=g, temporal_window_hours=24, min_strength=0.5)
        corrs = correlator.correlate_all()
        # Time diff >> window, no spatial, different labels => no correlation
        assert len(corrs) == 0

    def test_entity_correlation_same_label(self):
        """Nodes with the same label from different sources should entity-correlate."""
        g = IntelGraph()
        now = datetime.utcnow()
        g.add_node(Node(id="a", node_type="actor", label="Target Zero",
                        source_ids=["intel_a"], first_seen=now))
        g.add_node(Node(id="b", node_type="actor", label="Target Zero",
                        source_ids=["intel_b"], first_seen=now + timedelta(days=60)))
        correlator = CrossSourceCorrelator(
            graph=g, temporal_window_hours=24, min_strength=0.5)
        corrs = correlator.correlate_all()
        # Same label => entity match = 1.0
        assert len(corrs) >= 1
        assert any(c.strength >= 0.5 for c in corrs)


# ===================================================================
# 7. Config
# ===================================================================

class TestConfig:
    """Tests for guardian.config defaults."""

    def test_relay_models_has_3_entries(self):
        """RELAY_MODELS should have exactly 3 entries."""
        assert len(config.RELAY_MODELS) == 3
        assert "primary" in config.RELAY_MODELS
        assert "secondary" in config.RELAY_MODELS
        assert "tertiary" in config.RELAY_MODELS

    def test_confidence_threshold_default(self):
        """CONFIDENCE_THRESHOLD should default to 7."""
        assert config.CONFIDENCE_THRESHOLD == 7

    def test_relay_models_values_are_strings(self):
        for key, value in config.RELAY_MODELS.items():
            assert isinstance(value, str), f"RELAY_MODELS[{key!r}] is not a string"

    def test_eval_models_mirror_relay(self):
        """EVAL_MODELS should use the same models as RELAY_MODELS."""
        assert config.EVAL_MODELS["model_a"] == config.RELAY_MODELS["primary"]
        assert config.EVAL_MODELS["model_b"] == config.RELAY_MODELS["secondary"]
        assert config.EVAL_MODELS["model_c"] == config.RELAY_MODELS["tertiary"]


# ===================================================================
# 8. Evaluator format_evaluation
# ===================================================================

class TestFormatEvaluation:
    """Tests for the format_evaluation display function."""

    def test_format_evaluation_basic(self):
        """format_evaluation should produce a readable string from a mock result."""
        mock_result = {
            "confidence_level": "HIGH",
            "consensus_verdict": "THREAT",
            "consensus_score": 8.7,
            "agreement_map": {
                "anthropic/claude-sonnet-4-20250514": {
                    "verdict": "THREAT", "score": 9, "confidence": 95,
                    "agrees_with_consensus": True,
                },
                "xai/grok-3-mini-beta": {
                    "verdict": "THREAT", "score": 8, "confidence": 88,
                    "agrees_with_consensus": True,
                },
                "google/gemini-2.0-flash": {
                    "verdict": "THREAT", "score": 9, "confidence": 92,
                    "agrees_with_consensus": True,
                },
            },
            "verdicts": [],
            "reasoning_chain": "[+] Stage 1 (claude): THREAT (9/10) - Clear malicious pattern\n"
                               "[+] Stage 2 (grok): THREAT (8/10) - Confirmed persistence\n"
                               "[+] Stage 3 (gemini): THREAT (9/10) - Concur with prior evaluators",
            "elapsed": 4.2,
        }
        output = format_evaluation(mock_result)
        assert isinstance(output, str)
        assert "HIGH" in output
        assert "THREAT" in output
        assert "8.7" in output
        assert "4.2" in output
        assert "AGREE" in output
        assert "claude" in output  # model name substring
        assert "Stage 1" in output

    def test_format_evaluation_with_dissenter(self):
        """format_evaluation should show DISSENT for a disagreeing model."""
        mock_result = {
            "confidence_level": "MEDIUM",
            "consensus_verdict": "THREAT",
            "consensus_score": 6.0,
            "agreement_map": {
                "model_a": {
                    "verdict": "THREAT", "score": 8, "confidence": 80,
                    "agrees_with_consensus": True,
                },
                "model_b": {
                    "verdict": "BENIGN", "score": 3, "confidence": 70,
                    "agrees_with_consensus": False,
                },
                "model_c": {
                    "verdict": "THREAT", "score": 7, "confidence": 75,
                    "agrees_with_consensus": True,
                },
            },
            "verdicts": [],
            "reasoning_chain": "[+] Stage 1: THREAT\n[X] Stage 2: BENIGN\n[+] Stage 3: THREAT",
            "elapsed": 5.5,
        }
        output = format_evaluation(mock_result)
        assert "DISSENT" in output
        assert "MEDIUM" in output

    def test_format_evaluation_empty_agreement_map(self):
        """format_evaluation with empty agreement_map should not crash."""
        mock_result = {
            "confidence_level": "NONE",
            "consensus_verdict": "?",
            "consensus_score": 0,
            "agreement_map": {},
            "verdicts": [],
            "reasoning_chain": "All evaluators failed.",
            "elapsed": 0.1,
        }
        output = format_evaluation(mock_result)
        assert "NONE" in output
        assert "All evaluators failed" in output
