"""
Entity Resolution Engine
Deduplicates and merges entities across data sources.
Adapted from Jarvis entity_resolution.py.
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import difflib

from .graph import IntelGraph, Node


@dataclass
class ResolvedEntity:
    canonical_id: str
    canonical_label: str
    entity_type: str
    aliases: List[str]
    source_ids: List[str]
    source_node_ids: List[str]
    properties: Dict[str, Any]
    confidence: float
    first_seen: datetime
    last_seen: datetime

    def to_dict(self) -> Dict:
        return {
            "canonical_id": self.canonical_id,
            "canonical_label": self.canonical_label,
            "entity_type": self.entity_type,
            "aliases": self.aliases,
            "source_ids": self.source_ids,
            "source_node_ids": self.source_node_ids,
            "confidence": self.confidence,
        }


class EntityResolver:
    SKIP_RESOLUTION_TYPES = {'thermal_event', 'seismic_event', 'flight_track', 'acled_event'}

    def __init__(self, graph: IntelGraph = None, min_similarity: float = 0.7):
        self.graph = graph or IntelGraph()
        self.min_similarity = min_similarity
        self.blocking_key_size = 3

        self.known_aliases: Dict[str, Set[str]] = {
            "houthi": {"ansar allah", "houthi movement", "houthis", "ansarallah"},
            "hezbollah": {"hizbollah", "hizbullah", "hizballah", "party of god"},
            "hamas": {"izz ad-din al-qassam", "al-qassam brigades"},
            "isis": {"islamic state", "isil", "daesh", "is"},
            "usa": {"united states", "us", "america"},
            "uk": {"united kingdom", "britain", "great britain"},
        }

        self.alias_to_canonical: Dict[str, str] = {}
        for canonical, aliases in self.known_aliases.items():
            self.alias_to_canonical[canonical.lower()] = canonical
            for alias in aliases:
                self.alias_to_canonical[alias.lower()] = canonical

        self.resolved_entities: Dict[str, ResolvedEntity] = {}
        self.node_to_resolved: Dict[str, str] = {}

    def resolve_all(self) -> List[ResolvedEntity]:
        nodes = list(self.graph.nodes.values())
        if not nodes:
            return []

        by_type: Dict[str, List[Node]] = defaultdict(list)
        for node in nodes:
            by_type[node.node_type].append(node)

        all_resolved = []
        for entity_type, type_nodes in by_type.items():
            if entity_type in self.SKIP_RESOLUTION_TYPES:
                continue
            resolved = self._resolve_type(entity_type, type_nodes)
            all_resolved.extend(resolved)
        return all_resolved

    def _resolve_type(self, entity_type: str, nodes: List[Node]) -> List[ResolvedEntity]:
        if len(nodes) <= 1:
            return [self._node_to_resolved(nodes[0])] if nodes else []

        # Blocking
        blocks: Dict[str, List[Node]] = defaultdict(list)
        for node in nodes:
            keys = self._get_blocking_keys(node)
            for key in keys:
                blocks[key].append(node)

        # Pairwise comparison
        merge_pairs = []
        for block_nodes in blocks.values():
            for i, node1 in enumerate(block_nodes):
                for node2 in block_nodes[i + 1:]:
                    sim = self._calculate_similarity(node1, node2)
                    if sim >= self.min_similarity:
                        merge_pairs.append((node1.id, node2.id, sim))

        # Transitive closure (Union-Find)
        parent = {n.id: n.id for n in nodes}

        def find(x):
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        for n1_id, n2_id, _ in merge_pairs:
            union(n1_id, n2_id)

        node_map = {n.id: n for n in nodes}
        clusters: Dict[str, List[Node]] = defaultdict(list)
        for node in nodes:
            clusters[find(node.id)].append(node)

        resolved = []
        for cluster in clusters.values():
            re = self._merge_cluster(cluster)
            resolved.append(re)
            self.resolved_entities[re.canonical_id] = re
            for nid in re.source_node_ids:
                self.node_to_resolved[nid] = re.canonical_id
        return resolved

    def _get_blocking_keys(self, node: Node) -> List[str]:
        keys = []
        label = node.label.lower().strip()
        if len(label) >= self.blocking_key_size:
            keys.append(label[:self.blocking_key_size])
        canonical = self.alias_to_canonical.get(label)
        if canonical:
            keys.append(canonical[:self.blocking_key_size])
        words = label.split()
        if words:
            keys.append(words[0][:self.blocking_key_size])
        return keys

    def _calculate_similarity(self, node1: Node, node2: Node) -> float:
        name_sim = self._name_similarity(node1.label, node2.label)
        type_sim = 1.0 if node1.node_type == node2.node_type else 0.0
        return name_sim * 0.6 + type_sim * 0.2 + 0.1  # simplified

    def _name_similarity(self, name1: str, name2: str) -> float:
        n1, n2 = name1.lower().strip(), name2.lower().strip()
        if n1 == n2:
            return 1.0
        c1 = self.alias_to_canonical.get(n1)
        c2 = self.alias_to_canonical.get(n2)
        if c1 and c1 == c2:
            return 0.95
        ratio = difflib.SequenceMatcher(None, n1, n2).ratio()
        if n1 in n2 or n2 in n1:
            ratio = max(ratio, 0.8)
        return ratio

    def _merge_cluster(self, cluster: List[Node]) -> ResolvedEntity:
        if len(cluster) == 1:
            return self._node_to_resolved(cluster[0])

        labels = [n.label for n in cluster]
        canonical_label = max(labels, key=len)

        # Check known canonical
        for label in labels:
            canonical = self.alias_to_canonical.get(label.lower())
            if canonical:
                canonical_label = canonical.title()
                break

        all_sources = list(set(s for n in cluster for s in n.source_ids))
        merged_props = {}
        for node in cluster:
            merged_props.update(node.properties)

        return ResolvedEntity(
            canonical_id=f"resolved_{cluster[0].id}",
            canonical_label=canonical_label,
            entity_type=cluster[0].node_type,
            aliases=list(set(labels) - {canonical_label}),
            source_ids=all_sources,
            source_node_ids=[n.id for n in cluster],
            properties=merged_props,
            confidence=min(1.0, len(cluster) / 3),
            first_seen=min(n.first_seen for n in cluster),
            last_seen=max(n.last_seen for n in cluster),
        )

    def _node_to_resolved(self, node: Node) -> ResolvedEntity:
        return ResolvedEntity(
            canonical_id=f"resolved_{node.id}",
            canonical_label=node.label, entity_type=node.node_type,
            aliases=[], source_ids=node.source_ids,
            source_node_ids=[node.id], properties=node.properties,
            confidence=1.0, first_seen=node.first_seen,
            last_seen=node.last_seen,
        )

    def get_all_resolved(self) -> List[ResolvedEntity]:
        return list(self.resolved_entities.values())
