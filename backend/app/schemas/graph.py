"""IOC relationship graph payloads.

The graph is derived from normalized enrichment evidence: the root node is the
analyzed indicator, provider "source" nodes represent consulted providers, and
"indicator" nodes are related IOCs that providers explicitly associate with
the root (campaign membership, parent sample, ...). Fully serializable so the
React Flow frontend can render it as-is.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

NodeKind = Literal["root", "source", "evidence", "indicator"]


class GraphNode(BaseModel):
    id: str
    kind: NodeKind
    label: str
    indicator_type: str | None = None
    subtitle: str | None = None
    verdict: str | None = None
    score: int | None = None
    url: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str


class IOCGraph(BaseModel):
    root: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    generated_at: datetime = Field(default_factory=datetime.utcnow)