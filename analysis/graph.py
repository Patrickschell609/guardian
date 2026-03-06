"""
Intelligence Graph Store
In-memory graph database for entity relationships.
Adapted from Jarvis/Submarine graph_store.py.
"""

from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import json
import sqlite3


@dataclass
class Node:
    """Graph node representing an entity."""
    id: str
    node_type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    source_ids: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 1.0

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "node_type": self.node_type, "label": self.label,
            "properties": self.properties, "source_ids": self.source_ids,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "confidence": self.confidence,
        }


@dataclass
class Edge:
    """Graph edge representing a relationship."""
    id: str
    source_id: str
    target_id: str
    edge_type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    source_ids: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 1.0
    weight: float = 1.0

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "source_id": self.source_id,
            "target_id": self.target_id, "edge_type": self.edge_type,
            "properties": self.properties, "source_ids": self.source_ids,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "confidence": self.confidence, "weight": self.weight,
        }


class IntelGraph:
    """In-memory graph store with optional SQLite persistence."""

    def __init__(self, persist_path: Optional[str] = None):
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[str, Edge] = {}
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.node_edges: Dict[str, Set[str]] = defaultdict(set)
        self.persist_path = persist_path
        if persist_path:
            self._init_db()
            self._load_from_db()

    def add_node(self, node: Node) -> Node:
        if node.id in self.nodes:
            existing = self.nodes[node.id]
            for src in node.source_ids:
                if src not in existing.source_ids:
                    existing.source_ids.append(src)
            existing.last_seen = datetime.utcnow()
            existing.properties.update(node.properties)
            node = existing
        else:
            self.nodes[node.id] = node
        if self.persist_path:
            self._persist_node(node)
        return node

    def get_node(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)

    def get_nodes_by_type(self, node_type: str) -> List[Node]:
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def search_nodes(self, query: str, node_type: str = None) -> List[Node]:
        query_lower = query.lower()
        results = []
        for node in self.nodes.values():
            if node_type and node.node_type != node_type:
                continue
            if query_lower in node.label.lower():
                results.append(node)
        return results

    def add_edge(self, edge: Edge) -> Edge:
        if edge.id in self.edges:
            existing = self.edges[edge.id]
            for src in edge.source_ids:
                if src not in existing.source_ids:
                    existing.source_ids.append(src)
            existing.last_seen = datetime.utcnow()
            existing.weight += 1
            existing.properties.update(edge.properties)
            edge = existing
        else:
            self.edges[edge.id] = edge
            self.adjacency[edge.source_id].add(edge.target_id)
            self.reverse_adjacency[edge.target_id].add(edge.source_id)
            self.node_edges[edge.source_id].add(edge.id)
            self.node_edges[edge.target_id].add(edge.id)
        if self.persist_path:
            self._persist_edge(edge)
        return edge

    def get_neighbors(self, node_id: str, direction: str = "both") -> List[Node]:
        neighbor_ids = set()
        if direction in ("out", "both"):
            neighbor_ids.update(self.adjacency.get(node_id, set()))
        if direction in ("in", "both"):
            neighbor_ids.update(self.reverse_adjacency.get(node_id, set()))
        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]

    def find_path(self, start_id: str, end_id: str, max_depth: int = 6) -> Optional[List[str]]:
        if start_id not in self.nodes or end_id not in self.nodes:
            return None
        if start_id == end_id:
            return [start_id]
        visited = {start_id}
        queue = [(start_id, [start_id])]
        while queue:
            current, path = queue.pop(0)
            if len(path) > max_depth:
                continue
            for neighbor_id in self.adjacency.get(current, set()):
                if neighbor_id == end_id:
                    return path + [end_id]
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, path + [neighbor_id]))
        return None

    def get_connected_component(self, node_id: str) -> Set[str]:
        if node_id not in self.nodes:
            return set()
        visited = set()
        queue = [node_id]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            for neighbor in self.adjacency.get(current, set()):
                if neighbor not in visited:
                    queue.append(neighbor)
            for neighbor in self.reverse_adjacency.get(current, set()):
                if neighbor not in visited:
                    queue.append(neighbor)
        return visited

    def calculate_degree_centrality(self) -> Dict[str, float]:
        if not self.nodes:
            return {}
        max_possible = len(self.nodes) - 1
        if max_possible == 0:
            return {nid: 0.0 for nid in self.nodes}
        centrality = {}
        for node_id in self.nodes:
            degree = len(self.adjacency.get(node_id, set())) + len(self.reverse_adjacency.get(node_id, set()))
            centrality[node_id] = degree / max_possible
        return centrality

    def detect_communities(self) -> Dict[str, int]:
        communities = {}
        community_id = 0
        visited = set()
        for node_id in self.nodes:
            if node_id in visited:
                continue
            component = self.get_connected_component(node_id)
            for member in component:
                communities[member] = community_id
                visited.add(member)
            community_id += 1
        return communities

    def get_stats(self) -> Dict:
        node_types = defaultdict(int)
        edge_types = defaultdict(int)
        for node in self.nodes.values():
            node_types[node.node_type] += 1
        for edge in self.edges.values():
            edge_types[edge.edge_type] += 1
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "node_types": dict(node_types),
            "edge_types": dict(edge_types),
        }

    # SQLite persistence
    def _init_db(self):
        conn = sqlite3.connect(self.persist_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY, node_type TEXT, label TEXT,
            properties TEXT, source_ids TEXT, first_seen TEXT,
            last_seen TEXT, confidence REAL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS edges (
            id TEXT PRIMARY KEY, source_id TEXT, target_id TEXT,
            edge_type TEXT, properties TEXT, source_ids TEXT,
            first_seen TEXT, last_seen TEXT, confidence REAL, weight REAL)''')
        conn.commit()
        conn.close()

    def _load_from_db(self):
        conn = sqlite3.connect(self.persist_path)
        c = conn.cursor()
        for row in c.execute('SELECT * FROM nodes'):
            node = Node(
                id=row[0], node_type=row[1], label=row[2],
                properties=json.loads(row[3]), source_ids=json.loads(row[4]),
                first_seen=datetime.fromisoformat(row[5]),
                last_seen=datetime.fromisoformat(row[6]), confidence=row[7])
            self.nodes[node.id] = node
        for row in c.execute('SELECT * FROM edges'):
            edge = Edge(
                id=row[0], source_id=row[1], target_id=row[2],
                edge_type=row[3], properties=json.loads(row[4]),
                source_ids=json.loads(row[5]),
                first_seen=datetime.fromisoformat(row[6]),
                last_seen=datetime.fromisoformat(row[7]),
                confidence=row[8], weight=row[9])
            self.edges[edge.id] = edge
            self.adjacency[edge.source_id].add(edge.target_id)
            self.reverse_adjacency[edge.target_id].add(edge.source_id)
            self.node_edges[edge.source_id].add(edge.id)
            self.node_edges[edge.target_id].add(edge.id)
        conn.close()

    def _persist_node(self, node: Node):
        conn = sqlite3.connect(self.persist_path)
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                  (node.id, node.node_type, node.label,
                   json.dumps(node.properties), json.dumps(node.source_ids),
                   node.first_seen.isoformat(), node.last_seen.isoformat(),
                   node.confidence))
        conn.commit()
        conn.close()

    def _persist_edge(self, edge: Edge):
        conn = sqlite3.connect(self.persist_path)
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO edges VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                  (edge.id, edge.source_id, edge.target_id, edge.edge_type,
                   json.dumps(edge.properties), json.dumps(edge.source_ids),
                   edge.first_seen.isoformat(), edge.last_seen.isoformat(),
                   edge.confidence, edge.weight))
        conn.commit()
        conn.close()

    def save(self):
        if not self.persist_path:
            return
        for node in self.nodes.values():
            self._persist_node(node)
        for edge in self.edges.values():
            self._persist_edge(edge)


def get_graph(persist_path: Optional[str] = None) -> IntelGraph:
    """Get a graph instance."""
    from .. import config
    if persist_path is None:
        persist_path = config.GRAPH_DB
    return IntelGraph(persist_path)
