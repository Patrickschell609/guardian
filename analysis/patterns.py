"""
Pattern Detection Engine
Detects recurring entities, temporal clusters, network patterns, etc.
Adapted from Jarvis pattern_engine.py.
"""

from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import math

from .graph import IntelGraph, Node, Edge


class PatternType(str, Enum):
    RECURRING_ENTITY = "recurring_entity"
    SHARED_NETWORK = "shared_network"
    TEMPORAL_CLUSTER = "temporal_cluster"
    BEHAVIORAL_PATTERN = "behavioral_pattern"
    GEOGRAPHIC_CLUSTER = "geographic_cluster"
    ATTACK_PATTERN = "attack_pattern"
    SUPPLY_CHAIN = "supply_chain"


@dataclass
class Pattern:
    id: str
    pattern_type: PatternType
    entities: List[str]
    edges: List[str]
    sources: List[str]
    confidence: float
    detected_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "pattern_type": self.pattern_type.value,
            "entities": self.entities, "edges": self.edges,
            "sources": self.sources, "confidence": self.confidence,
            "detected_at": self.detected_at.isoformat(),
            "metadata": self.metadata, "description": self.description,
        }


@dataclass
class PatternConfig:
    min_entities_for_pattern: int = 2
    min_sources_for_pattern: int = 2
    min_confidence: float = 0.5
    temporal_window_hours: int = 24
    geographic_radius_km: float = 50.0
    max_patterns_per_run: int = 100


class PatternEngine:
    def __init__(self, graph: IntelGraph = None, config: PatternConfig = None):
        self.graph = graph or IntelGraph()
        self.config = config or PatternConfig()
        self.patterns: Dict[str, Pattern] = {}
        self.pattern_counter = 0

    def _generate_pattern_id(self, pattern_type: PatternType) -> str:
        self.pattern_counter += 1
        return f"pattern_{pattern_type.value}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{self.pattern_counter}"

    def detect_all(self) -> List[Pattern]:
        nodes = list(self.graph.nodes.values())
        edges = list(self.graph.edges.values())
        if not nodes:
            return []

        all_patterns = []
        all_patterns.extend(self.detect_recurring_entities(nodes))
        all_patterns.extend(self.detect_shared_networks(nodes, edges))
        all_patterns.extend(self.detect_temporal_clusters(nodes))
        all_patterns.extend(self.detect_attack_patterns(nodes, edges))

        for pattern in all_patterns:
            self.patterns[pattern.id] = pattern

        all_patterns.sort(key=lambda p: p.confidence, reverse=True)
        return all_patterns[:self.config.max_patterns_per_run]

    def detect_recurring_entities(self, nodes: List[Node]) -> List[Pattern]:
        patterns = []
        for node in nodes:
            if len(node.source_ids) >= self.config.min_sources_for_pattern:
                confidence = min(1.0, len(node.source_ids) / 5)
                if confidence >= self.config.min_confidence:
                    patterns.append(Pattern(
                        id=self._generate_pattern_id(PatternType.RECURRING_ENTITY),
                        pattern_type=PatternType.RECURRING_ENTITY,
                        entities=[node.id], edges=[], sources=node.source_ids,
                        confidence=confidence, detected_at=datetime.utcnow(),
                        metadata={"entity_type": node.node_type, "label": node.label},
                        description=f"{node.label} appears in {len(node.source_ids)} sources"
                    ))
        return patterns

    def detect_shared_networks(self, nodes: List[Node], edges: List[Edge]) -> List[Pattern]:
        patterns = []
        visited = set()
        for node in nodes:
            if node.id in visited:
                continue
            component = self.graph.get_connected_component(node.id)
            visited.update(component)
            if len(component) < self.config.min_entities_for_pattern:
                continue
            all_sources = set()
            for node_id in component:
                n = self.graph.get_node(node_id)
                if n:
                    all_sources.update(n.source_ids)
            if len(all_sources) < self.config.min_sources_for_pattern:
                continue
            component_edges = [e.id for e in edges if e.source_id in component and e.target_id in component]
            confidence = min(1.0, len(component) / 10) * min(1.0, len(all_sources) / 3)
            if confidence >= self.config.min_confidence:
                patterns.append(Pattern(
                    id=self._generate_pattern_id(PatternType.SHARED_NETWORK),
                    pattern_type=PatternType.SHARED_NETWORK,
                    entities=list(component), edges=component_edges,
                    sources=list(all_sources), confidence=confidence,
                    detected_at=datetime.utcnow(),
                    metadata={"network_size": len(component)},
                    description=f"Network of {len(component)} entities across {len(all_sources)} sources"
                ))
        return patterns

    def detect_temporal_clusters(self, nodes: List[Node]) -> List[Pattern]:
        patterns = []
        window = timedelta(hours=self.config.temporal_window_hours)
        sorted_nodes = sorted(nodes, key=lambda n: n.first_seen)
        if not sorted_nodes:
            return []

        buckets = []
        bucket_start = sorted_nodes[0].first_seen
        current_bucket = []
        for node in sorted_nodes:
            if node.first_seen - bucket_start > window:
                if current_bucket:
                    buckets.append(current_bucket)
                current_bucket = [node]
                bucket_start = node.first_seen
            else:
                current_bucket.append(node)
        if current_bucket:
            buckets.append(current_bucket)

        for bucket in buckets:
            if len(bucket) < self.config.min_entities_for_pattern:
                continue
            all_sources = set()
            for n in bucket:
                all_sources.update(n.source_ids)
            if len(all_sources) < self.config.min_sources_for_pattern:
                continue
            count_factor = min(1.0, math.log10(len(bucket) + 1) / 3)
            source_factor = min(1.0, len(all_sources) / 3)
            confidence = count_factor * source_factor
            if confidence >= self.config.min_confidence:
                patterns.append(Pattern(
                    id=self._generate_pattern_id(PatternType.TEMPORAL_CLUSTER),
                    pattern_type=PatternType.TEMPORAL_CLUSTER,
                    entities=[n.id for n in bucket[:50]], edges=[],
                    sources=list(all_sources), confidence=confidence,
                    detected_at=datetime.utcnow(),
                    metadata={"cluster_size": len(bucket),
                              "window_start": bucket[0].first_seen.isoformat(),
                              "window_end": bucket[-1].first_seen.isoformat()},
                    description=f"{len(bucket)} events in {self.config.temporal_window_hours}h window"
                ))
        return patterns

    def detect_attack_patterns(self, nodes: List[Node], edges: List[Edge]) -> List[Pattern]:
        patterns = []
        actor_attacks = defaultdict(list)
        for edge in edges:
            if edge.edge_type in ("attacks", "targets", "strikes"):
                actor_attacks[edge.source_id].append(edge)

        for actor_id, attacks in actor_attacks.items():
            if len(attacks) < self.config.min_entities_for_pattern:
                continue
            actor = self.graph.get_node(actor_id)
            if not actor:
                continue
            target_ids = [e.target_id for e in attacks]
            all_sources = set(actor.source_ids)
            for tid in target_ids:
                t = self.graph.get_node(tid)
                if t:
                    all_sources.update(t.source_ids)
            if len(all_sources) >= self.config.min_sources_for_pattern:
                confidence = min(1.0, len(attacks) / 5)
                if confidence >= self.config.min_confidence:
                    patterns.append(Pattern(
                        id=self._generate_pattern_id(PatternType.ATTACK_PATTERN),
                        pattern_type=PatternType.ATTACK_PATTERN,
                        entities=[actor_id] + target_ids,
                        edges=[e.id for e in attacks],
                        sources=list(all_sources), confidence=confidence,
                        detected_at=datetime.utcnow(),
                        metadata={"actor": actor.label, "target_count": len(attacks)},
                        description=f"{actor.label} linked to {len(attacks)} attack events"
                    ))
        return patterns

    def get_all_patterns(self) -> List[Pattern]:
        return list(self.patterns.values())
