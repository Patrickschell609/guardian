"""
Cross-Source Correlator
Finds correlations between events across different data sources.
Adapted from Jarvis cross_source.py.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import math

from .graph import IntelGraph, Node


class CorrelationType(str, Enum):
    TEMPORAL = "temporal"
    SPATIAL = "spatial"
    ENTITY = "entity"
    CAUSAL = "causal"
    FINANCIAL = "financial"
    NETWORK = "network"


@dataclass
class Correlation:
    id: str
    correlation_type: CorrelationType
    source_a: str
    source_b: str
    event_a_id: str
    event_b_id: str
    strength: float
    evidence: Dict[str, Any]
    detected_at: datetime
    description: str

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "correlation_type": self.correlation_type.value,
            "source_a": self.source_a, "source_b": self.source_b,
            "event_a_id": self.event_a_id, "event_b_id": self.event_b_id,
            "strength": self.strength, "evidence": self.evidence,
            "detected_at": self.detected_at.isoformat(),
            "description": self.description,
        }


class CrossSourceCorrelator:
    def __init__(self, graph: IntelGraph = None, temporal_window_hours: int = 24,
                 spatial_radius_km: float = 50.0, min_strength: float = 0.5):
        self.graph = graph or IntelGraph()
        self.temporal_window_hours = temporal_window_hours
        self.spatial_radius_km = spatial_radius_km
        self.min_strength = min_strength
        self.correlations: Dict[str, Correlation] = {}
        self.counter = 0

    def _gen_id(self) -> str:
        self.counter += 1
        return f"corr_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{self.counter}"

    def correlate_all(self) -> List[Correlation]:
        nodes = list(self.graph.nodes.values())
        if len(nodes) < 2:
            return []

        by_source: Dict[str, List[Node]] = defaultdict(list)
        for node in nodes:
            for source in node.source_ids:
                by_source[source].append(node)

        all_correlations = []
        sources = list(by_source.keys())
        for i, source_a in enumerate(sources):
            for source_b in sources[i + 1:]:
                correlations = self._correlate_sources(
                    source_a, by_source[source_a],
                    source_b, by_source[source_b]
                )
                all_correlations.extend(correlations)

        for corr in all_correlations:
            self.correlations[corr.id] = corr
        return all_correlations

    def _correlate_sources(self, source_a: str, nodes_a: List[Node],
                           source_b: str, nodes_b: List[Node]) -> List[Correlation]:
        correlations = []
        for node_a in nodes_a:
            for node_b in nodes_b:
                temporal = self._check_temporal(node_a, node_b)
                spatial = self._check_spatial(node_a, node_b)
                entity = self._check_entity(node_a, node_b)

                if temporal or spatial or entity:
                    strength = max(temporal or 0, spatial or 0, entity or 0)
                    if strength >= self.min_strength:
                        t, s, e = temporal or 0, spatial or 0, entity or 0
                        if e >= t and e >= s:
                            corr_type = CorrelationType.ENTITY
                        elif t >= s:
                            corr_type = CorrelationType.TEMPORAL
                        else:
                            corr_type = CorrelationType.SPATIAL

                        correlations.append(Correlation(
                            id=self._gen_id(), correlation_type=corr_type,
                            source_a=source_a, source_b=source_b,
                            event_a_id=node_a.id, event_b_id=node_b.id,
                            strength=strength,
                            evidence={"temporal": temporal, "spatial": spatial, "entity": entity,
                                      "label_a": node_a.label, "label_b": node_b.label},
                            detected_at=datetime.utcnow(),
                            description=f"Cross-source: {node_a.label} <-> {node_b.label}"
                        ))
        return correlations

    def _check_temporal(self, node_a: Node, node_b: Node) -> Optional[float]:
        window = timedelta(hours=self.temporal_window_hours)
        time_diff = abs((node_a.first_seen - node_b.first_seen).total_seconds())
        window_seconds = window.total_seconds()
        if time_diff <= window_seconds:
            return 1.0 - (time_diff / window_seconds)
        return None

    def _check_spatial(self, node_a: Node, node_b: Node) -> Optional[float]:
        lat_a, lon_a = node_a.properties.get("lat"), node_a.properties.get("lon")
        lat_b, lon_b = node_b.properties.get("lat"), node_b.properties.get("lon")
        if None in (lat_a, lon_a, lat_b, lon_b):
            return None
        R = 6371
        lat1_rad, lat2_rad = math.radians(lat_a), math.radians(lat_b)
        dlat, dlon = math.radians(lat_b - lat_a), math.radians(lon_b - lon_a)
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad)*math.cos(lat2_rad)*math.sin(dlon/2)**2
        distance = R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        if distance <= self.spatial_radius_km:
            return 1.0 - (distance / self.spatial_radius_km)
        return None

    def _check_entity(self, node_a: Node, node_b: Node) -> Optional[float]:
        if node_a.label.lower() == node_b.label.lower():
            return 1.0
        shared_props = set(node_a.properties.keys()) & set(node_b.properties.keys())
        if shared_props:
            matches = sum(1 for k in shared_props if node_a.properties[k] == node_b.properties[k])
            if matches > 0:
                return min(1.0, matches / len(shared_props))
        path = self.graph.find_path(node_a.id, node_b.id, max_depth=3)
        if path:
            return 1.0 / len(path)
        return None

    def get_all_correlations(self) -> List[Correlation]:
        return list(self.correlations.values())
