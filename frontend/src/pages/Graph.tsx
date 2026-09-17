import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Network } from 'lucide-react'
import { useMemo } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  MarkerType,
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  Position,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'

import { PageHeader } from '../components/ui/PageHeader'
import { Panel } from '../components/ui/Panel'
import { Button } from '../components/ui/Button'
import { EmptyState } from '../components/ui/EmptyState'
import { Spinner } from '../components/ui/Spinner'
import { fetchGraph } from '../services/api'
import type { GraphNode, GraphNodeKind, IOCGraph } from '../types'
import { cn } from '../utils/cn'

const KIND_STYLES: Record<GraphNodeKind, { ring: string; chip: string; tint: string }> = {
  root: {
    ring: 'ring-emerald-400/30',
    chip: 'bg-emerald-400/15 text-emerald-300',
    tint: 'border-emerald-400/30',
  },
  source: {
    ring: 'ring-sky-400/30',
    chip: 'bg-sky-400/15 text-sky-300',
    tint: 'border-sky-400/30',
  },
  evidence: {
    ring: 'ring-violet-400/30',
    chip: 'bg-violet-400/15 text-violet-300',
    tint: 'border-violet-400/30',
  },
  indicator: {
    ring: 'ring-amber-400/30',
    chip: 'bg-amber-400/15 text-amber-300',
    tint: 'border-amber-400/30',
  },
}

function GraphNodeCard({ data, selected }: NodeProps<Node<{ node: GraphNode }>>) {
  const { node } = data
  const styles = KIND_STYLES[node.kind]!
  return (
    <div
      className={cn(
        'w-52 rounded-xl border bg-[#0d1420] p-3 shadow-lg ring-4 transition',
        'border-slate-700/60',
        styles.tint,
        selected ? 'ring-white/20' : styles.ring,
      )}
    >
      <Handle type="target" position={Position.Left} className="!bg-slate-500" />
      <div className="flex items-start justify-between gap-2">
        <p
          className={cn(
            'font-mono text-[11px] leading-tight text-slate-100',
            node.kind === 'indicator' && 'break-all',
          )}
          title={node.label}
        >
          {node.label}
        </p>
        <span
          className={cn(
            'shrink-0 rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide',
            styles.chip,
          )}
        >
          {node.kind}
        </span>
      </div>
      {node.subtitle ? (
        <p className="mt-1.5 line-clamp-2 text-[10px] text-slate-400">{node.subtitle}</p>
      ) : null}
      {node.indicator_type ? (
        <p className="mt-1 text-[9px] uppercase tracking-wider text-slate-500">
          {node.indicator_type}
        </p>
      ) : null}
      <Handle type="source" position={Position.Right} className="!bg-slate-500" />
    </div>
  )
}

const nodeTypes = { graph: GraphNodeCard } as const

const NODE_IDENTIFIER = { width: 208, height: 96 }

function buildLayout(graph: IOCGraph): { nodes: Node[]; edges: Edge[] } {
  const byId: Record<string, GraphNode> = {}
  for (const node of graph.nodes) byId[node.id] = node

  const positions: Record<string, { x: number; y: number }> = {}
  const columnHeights: Record<'source' | 'evidence' | 'indicator', number> = {
    source: 0,
    evidence: 0,
    indicator: 0,
  }

  positions[graph.root] = { x: 0, y: 0 }

  for (const node of graph.nodes) {
    if (node.id === graph.root) continue
    if (node.kind === 'source') {
      positions[node.id] = { x: 300, y: columnHeights.source }
      columnHeights.source += 130
    } else if (node.kind === 'evidence') {
      positions[node.id] = { x: 620, y: columnHeights.evidence }
      columnHeights.evidence += 116
    } else {
      positions[node.id] = { x: 980, y: columnHeights.indicator }
      columnHeights.indicator += 116
    }
  }

  const nodes: Node[] = graph.nodes.map((node) => ({
    id: node.id,
    type: 'graph',
    position: positions[node.id] ?? { x: 0, y: 0 },
    data: { node },
    style: NODE_IDENTIFIER,
  }))

  const edges: Edge[] = graph.edges.map((edge, index) => ({
    id: `edge-${index}`,
    source: edge.source,
    target: edge.target,
    label: edge.relation,
    type: 'smoothstep',
    labelStyle: {
      fontSize: 9,
      fill: '#94a3b8',
      fontFamily: 'JetBrains Mono, monospace',
    },
    labelBgStyle: { fill: '#0d1420', fillOpacity: 0.8 },
    style: { stroke: '#475569', strokeWidth: 1 },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      width: 16,
      height: 16,
      color: '#475569',
    },
  }))

  return { nodes, edges }
}

export function GraphPage() {
  const { analysisId = '' } = useParams()
  const navigate = useNavigate()

  const graph = useQuery({
    queryKey: ['graph', analysisId],
    queryFn: () => fetchGraph(analysisId),
    enabled: Boolean(analysisId),
  })

  const { nodes, edges } = useMemo(
    () => (graph.data ? buildLayout(graph.data) : { nodes: [] as Node[], edges: [] as Edge[] }),
    [graph.data],
  )

  const error = graph.error

  return (
    <div className="flex h-full flex-col space-y-5">
      <PageHeader
        title="IOC Relationship Graph"
        description="Providers, evidence and related indicators connected to the analyzed IOC."
        action={
          <Button variant="secondary" onClick={() => navigate(-1)}>
            <ArrowLeft className="h-4 w-4" />
            Back
          </Button>
        }
      />

      {graph.isPending ? (
        <Panel>
          <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
            <Spinner className="h-5 w-5" />
            Building graph…
          </div>
        </Panel>
      ) : error || !graph.data ? (
        <Panel>
          <EmptyState
            title="Graph could not be loaded"
            description={error instanceof Error ? error.message : 'Unknown error.'}
          />
        </Panel>
      ) : graph.data.nodes.length <= 1 ? (
        <Panel>
          <EmptyState
            title="Not enough evidence yet"
            description="Run an analysis with multi-provider enrichment enabled to unlock the relationship graph."
            action={
              <Button variant="secondary" onClick={() => navigate(`/analysis/${analysisId}`)}>
                <Network className="h-4 w-4" />
                Open analysis
              </Button>
            }
          />
        </Panel>
      ) : (
        <Panel className="min-h-[560px] flex-1 !p-0">
          <div className="h-[620px] w-full">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.25 }}
              minZoom={0.25}
              defaultEdgeOptions={{ deletable: false }}
              nodesConnectable={false}
              proOptions={{ hideAttribution: true }}
            >
              <Background variant={BackgroundVariant.Dots} gap={26} size={1.2} color="#1e293b" />
              <Controls />
              <MiniMap
                nodeColor={(node) => {
                  const kind = (node.data as { node: GraphNode }).node.kind
                  const colors = {
                    root: '#34d399',
                    source: '#38bdf8',
                    evidence: '#a78bfa',
                    indicator: '#fbbf24',
                  } as const
                  return colors[kind]
                }}
              />
              <div className="pointer-events-none absolute left-3 top-3 z-10 space-y-1.5 font-mono text-[10px] text-slate-400">
                <LegendDot color="#34d399" label="root indicator" />
                <LegendDot color="#38bdf8" label="provider source" />
                <LegendDot color="#a78bfa" label="evidence item" />
                <LegendDot color="#fbbf24" label="related IOC" />
              </div>
            </ReactFlow>
          </div>
        </Panel>
      )}
    </div>
  )
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
      {label}
    </div>
  )
}