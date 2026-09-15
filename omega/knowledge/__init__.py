"""Asset Graph — structured reasoning over engagement assets and relationships."""

from __future__ import annotations

import json
from typing import Any

from omega.core.schemas import GraphNode, GraphEdge, NodeType, EdgeType, new_id, now_utc
from omega.storage import Database


class AssetGraph:
    """In-memory + persistent graph for reasoning about assets."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: dict[str, dict[str, Any]] = {}
        self._adjacency: dict[str, list[str]] = {}  # node_id -> [edge_ids]

    async def load(self, engagement_id: str) -> None:
        """Load graph from database into memory."""
        nodes = await self.db.get_graph_nodes(engagement_id)
        edges = await self.db.get_graph_edges(engagement_id)
        for n in nodes:
            self._nodes[n["id"]] = n
        for e in edges:
            self._edges[e["id"]] = e
            src = e["source_node_id"]
            if src not in self._adjacency:
                self._adjacency[src] = []
            self._adjacency[src].append(e["id"])

    async def add_node(self, engagement_id: str, node_type: str, label: str, properties: dict[str, Any] | None = None) -> GraphNode:
        # Check for duplicates
        for nid, n in self._nodes.items():
            if n["engagement_id"] == engagement_id and n["node_type"] == node_type and n["label"] == label:
                return GraphNode(**n)

        node = GraphNode(
            id=new_id(),
            engagement_id=engagement_id,
            node_type=node_type,
            label=label,
            properties=properties or {},
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        saved = await self.db.save_graph_node(node.model_dump())
        self._nodes[node.id] = saved
        return node

    async def add_edge(self, engagement_id: str, source_id: str, target_id: str, edge_type: str, properties: dict[str, Any] | None = None) -> GraphEdge:
        # Dedup
        for eid, e in self._edges.items():
            if (e["source_node_id"] == source_id and e["target_node_id"] == target_id and e["edge_type"] == edge_type):
                return GraphEdge(**e)

        edge = GraphEdge(
            id=new_id(),
            engagement_id=engagement_id,
            source_node_id=source_id,
            target_node_id=target_id,
            edge_type=edge_type,
            properties=properties or {},
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        saved = await self.db.save_graph_edge(edge.model_dump())
        self._edges[edge.id] = saved
        if source_id not in self._adjacency:
            self._adjacency[source_id] = []
        self._adjacency[source_id].append(edge.id)
        return edge

    def get_neighbors(self, node_id: str, edge_type: str | None = None) -> list[dict[str, Any]]:
        """Get nodes connected via outgoing edges."""
        result = []
        for eid in self._adjacency.get(node_id, []):
            edge = self._edges.get(eid, {})
            if edge_type and edge.get("edge_type") != edge_type:
                continue
            target_id = edge.get("target_node_id", "")
            if target_id in self._nodes:
                result.append({**self._nodes[target_id], "_edge": edge})
        return result

    def get_reverse_neighbors(self, node_id: str, edge_type: str | None = None) -> list[dict[str, Any]]:
        """Get nodes connected via incoming edges."""
        result = []
        for eid, edge in self._edges.items():
            if edge.get("target_node_id") != node_id:
                continue
            if edge_type and edge.get("edge_type") != edge_type:
                continue
            src_id = edge.get("source_node_id", "")
            if src_id in self._nodes:
                result.append({**self._nodes[src_id], "_edge": edge})
        return result

    def find_nodes(self, engagement_id: str, node_type: str | None = None, label_contains: str | None = None) -> list[dict[str, Any]]:
        results = []
        for n in self._nodes.values():
            if n["engagement_id"] != engagement_id:
                continue
            if node_type and n["node_type"] != node_type:
                continue
            if label_contains and label_contains.lower() not in n["label"].lower():
                continue
            results.append(n)
        return results

    def find_path(self, source_id: str, target_id: str, max_depth: int = 5) -> list[dict[str, Any]] | None:
        """BFS path finding."""
        if source_id == target_id:
            return []
        visited = {source_id}
        queue = [(source_id, [])]
        for _ in range(max_depth):
            next_queue = []
            for current, path in queue:
                for eid in self._adjacency.get(current, []):
                    edge = self._edges.get(eid, {})
                    next_id = edge.get("target_node_id", "")
                    if next_id == target_id:
                        return path + [edge]
                    if next_id not in visited:
                        visited.add(next_id)
                        next_queue.append((next_id, path + [edge]))
            queue = next_queue
        return None

    def to_dict(self, engagement_id: str) -> dict[str, Any]:
        nodes = [n for n in self._nodes.values() if n["engagement_id"] == engagement_id]
        edges = [e for e in self._edges.values() if e["engagement_id"] == engagement_id]
        return {"nodes": nodes, "edges": edges, "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "node_types": list(set(n["node_type"] for n in nodes)),
            "edge_types": list(set(e["edge_type"] for e in edges)),
        }}
