"""Build an explainable IOC relationship graph from enrichment evidence.

The graph decomposes into three layers that the React Flow view renders as
clusters:

* ``root`` — the analyzed indicator.
* ``source`` — one node per provider that produced evidence.
* ``evidence`` — individual normalized evidence items under their source.
* ``indicator`` — related IOCs that providers explicitly associate with the
  root (e.g. OTX pulse campaign members).

All node ids are deterministic, so re-renders and cached payloads produce the
same layout keys.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Sequence

from app.schemas.analysis import IndicatorType
from app.schemas.enrichment import NormalizedEvidence
from app.schemas.graph import GraphEdge, GraphNode, IOCGraph
from app.utils.ioc import canonical_value


def _node_id(kind: str, value: str) -> str:
    return f"{kind}:{sha256(value.encode('utf-8')).hexdigest()[:16]}"


def _evidence_node(
    evidence: NormalizedEvidence, related: bool = False
) -> GraphNode:
    return GraphNode(
        id=_node_id("evidence", evidence.id),
        kind="evidence",
        label=evidence.title,
        subtitle=evidence.value[:120],
        verdict=(
            evidence.verdict if evidence.verdict not in {None, "unknown"} else None
        ),
        score=None,
        url=evidence.source_ref,
        meta={
            "source": evidence.provider,
            "evidence_type": evidence.evidence_type,
            "confidence": evidence.confidence,
        },
    )


def _related_from_evidence(
    evidence: NormalizedEvidence,
    root_indicator: str,
) -> list[tuple[str, str, str]]:
    """Yield (canonical_value, indicator_type, relation) for related IOCs."""
    meta = evidence.metadata or {}
    for record in meta.get("related") or []:
        if not isinstance(record, dict):
            continue
        raw = record.get("value")
        ioc_type = record.get("type")
        if not raw or ioc_type not in {"HASH", "FILE", "DOMAIN", "IP", "URL"}:
            continue
        canonical = canonical_value(ioc_type, str(raw))
        if not canonical or canonical == root_indicator:
            continue
        yield canonical, ioc_type, record.get("relation") or "related"


def build_ioc_graph(
    indicator: str,
    indicator_type: IndicatorType,
    evidence: Sequence[NormalizedEvidence] | None,
) -> IOCGraph:
    """Assemble the graph for one analyzed indicator."""
    root_id = "root"
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    nodes.append(
        GraphNode(
            id=root_id,
            kind="root",
            label=indicator,
            indicator_type=indicator_type,
            subtitle="analyzed indicator",
        )
    )

    if evidence:
        by_provider: dict[str, list[NormalizedEvidence]] = {}
        for item in evidence:
            by_provider.setdefault(item.provider, []).append(item)

        for provider, items in by_provider.items():
            source_id = _node_id("source", provider)
            nodes.append(
                GraphNode(
                    id=source_id,
                    kind="source",
                    label=provider,
                    subtitle=f"{len(items)} evidence item(s)",
                )
            )
            edges.append(
                GraphEdge(source=root_id, target=source_id, relation="queried")
            )
            seen: set[str] = set()
            for item in items:
                ev_id = _node_id("evidence", item.id)
                if ev_id in seen:
                    continue
                seen.add(ev_id)
                nodes.append(_evidence_node(item))
                edges.append(
                    GraphEdge(
                        source=source_id,
                        target=ev_id,
                        relation=str(item.evidence_type),
                    )
                )
                for related_value, ioc_type, relation in _related_from_evidence(
                    item, indicator
                ):
                    related_id = _node_id("indicator", related_value)
                    if all(node.id != related_id for node in nodes):
                        nodes.append(
                            GraphNode(
                                id=related_id,
                                kind="indicator",
                                label=related_value,
                                indicator_type=ioc_type,
                                subtitle=relation,
                            )
                        )
                    edges.append(
                        GraphEdge(
                            source=root_id,
                            target=related_id,
                            relation=relation,
                        )
                    )

    # Deterministic ordering so repeated renders are stable.
    nodes.sort(key=lambda node: node.id)
    edges.sort(key=lambda edge: (edge.source, edge.target, edge.relation))

    return IOCGraph(root=root_id, nodes=nodes, edges=edges)