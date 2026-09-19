import { useCallback, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowLeft,
  ArrowRight,
  FileCode2,
  Fingerprint,
  Globe,
  Globe2,
  Link2,
  Network,
} from 'lucide-react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
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
import { LevelBadge } from '../components/analysis/LevelBadge'
import { formatDate, shortId } from '../components/analysis/level'
import { fetchGraph } from '../services/api'
import { useI18n } from '../i18n'
import type {
  GraphNode,
  GraphNodeKind,
  IndicatorType,
  IOCGraph,
  ThreatLevel,
} from '../types'
import { cn } from '../utils/cn'

const KIND_STYLES: Record<
  GraphNodeKind,
  { ring: string; chip: string; tint: string; accent: string }
> = {
  root: {
    ring: 'ring-emerald-400/30',
    chip: 'bg-emerald-400/15 text-emerald-300',
    tint: 'border-emerald-400/30',
    accent: 'text-emerald-300',
  },
  source: {
    ring: 'ring-teal-400/30',
    chip: 'bg-teal-400/15 text-teal-300',
    tint: 'border-teal-400/30',
    accent: 'text-teal-300',
  },
  evidence: {
    ring: 'ring-violet-400/30',
    chip: 'bg-violet-400/15 text-violet-300',
    tint: 'border-violet-400/30',
    accent: 'text-violet-300',
  },
  indicator: {
    ring: 'ring-amber-400/30',
    chip: 'bg-amber-400/15 text-amber-300',
    tint: 'border-amber-400/30',
    accent: 'text-amber-300',
  },
}

const TYPE_ICONS: Partial<Record<IndicatorType, typeof Fingerprint>> = {
  HASH: Fingerprint,
  IP: Globe,
  URL: Link2,
  DOMAIN: Globe2,
  FILE: FileCode2,
}

function levelOf(value: string | null | undefined): ThreatLevel | null {
  if (
    value === 'clean' ||
    value === 'suspicious' ||
    value === 'malicious' ||
    value === 'critical'
  ) {
    return value
  }
  return null
}

function scoreClass(score: number | null): string {
  if (score == null) return 'text-ink-3 border-border'
  if (score >= 80) return 'text-critical border-critical/40'
  if (score >= 50) return 'text-elevated border-elevated/40'
  if (score >= 25) return 'text-ink border-border-strong'
  return 'text-ok border-ok/30'
}

function GraphNodeCard({ data, selected }: NodeProps<Node<{ node: GraphNode }>>) {
  const { node } = data
  const { t } = useI18n()
  const styles = KIND_STYLES[node.kind]!
  const Icon = (node.indicator_type && TYPE_ICONS[node.indicator_type]) || Network

  return (
    <div
      className={cn(
        'w-52 rounded-xl border bg-[#0d1420] p-3 shadow-lg ring-4 transition',
        'border-slate-700/60',
        styles.tint,
        selected ? 'ring-white/25' : styles.ring,
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
            'grid h-6 w-6 shrink-0 place-items-center rounded-md',
            styles.chip,
          )}
        >
          <Icon className="h-3.5 w-3.5" />
        </span>
      </div>
      {node.subtitle ? (
        <p className="mt-1.5 line-clamp-2 text-[10px] text-slate-400">
          {node.subtitle}
        </p>
      ) : null}
      <div className="mt-2 flex items-center justify-between gap-2">
        {node.indicator_type ? (
          <span className="text-[9px] tracking-wider text-slate-500 uppercase">
            {t(`type.${node.indicator_type}`)}
          </span>
        ) : (
          <span
            className={cn(
              'shrink-0 rounded px-1.5 py-0.5 text-[9px] font-semibold tracking-wide uppercase',
              styles.chip,
            )}
          >
            {t(`kind.${node.kind}`)}
          </span>
        )}
        {node.score != null && (
          <span
            className={cn(
              'rounded border px-1.5 py-0.5 font-mono text-[10.5px] font-semibold tabular-nums',
              scoreClass(node.score),
            )}
          >
            {node.score}
          </span>
        )}
      </div>
      <Handle type="source" position={Position.Right} className="!bg-slate-500" />
    </div>
  )
}

const nodeTypes = { graph: GraphNodeCard } as const

const NODE_IDENTIFIER = { width: 208, height: 118 }

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
      columnHeights.source += 140
    } else if (node.kind === 'evidence') {
      positions[node.id] = { x: 640, y: columnHeights.evidence }
      columnHeights.evidence += 136
    } else {
      positions[node.id] = { x: 990, y: columnHeights.indicator }
      columnHeights.indicator += 136
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
  const { t } = useI18n()

  const graph = useQuery({
    queryKey: ['graph', analysisId],
    queryFn: () => fetchGraph(analysisId),
    enabled: Boolean(analysisId),
  })

  const { nodes, edges } = useMemo(
    () =>
      graph.data
        ? buildLayout(graph.data)
        : { nodes: [] as Node[], edges: [] as Edge[] },
    [graph.data],
  )

  const [selected, setSelected] = useState<GraphNode | null>(null)

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    setSelected((node.data as { node: GraphNode }).node)
  }, [])

  const error = graph.error
  const isRoot = selected?.id === graph.data?.root

  return (
    <div className="flex h-full flex-col space-y-5">
      <PageHeader
        title={t('IOC Relationship Graph')}
        description={t(
          'Providers, evidence and related indicators connected to the analyzed IOC.',
        )}
        action={
          <Button variant="secondary" onClick={() => navigate(-1)}>
            <ArrowLeft className="h-4 w-4" />
            {t('Back')}
          </Button>
        }
      />

      {graph.isPending ? (
        <Panel>
          <div className="flex items-center justify-center gap-3 py-14 text-ink-2">
            <Spinner className="h-5 w-5" />
            {t('Building graph…')}
          </div>
        </Panel>
      ) : error || !graph.data ? (
        <Panel>
          <EmptyState
            title={t('Graph could not be loaded')}
            description={
              error instanceof Error ? error.message : t('Unknown error.')
            }
          />
        </Panel>
      ) : graph.data.nodes.length <= 1 ? (
        <Panel>
          <EmptyState
            title={t('Not enough evidence yet')}
            description={t(
              'Run an analysis with multi-provider enrichment enabled to unlock the relationship graph.',
            )}
            action={
              <Button
                variant="secondary"
                onClick={() => navigate(`/analysis/${analysisId}`)}
              >
                <Network className="h-4 w-4" />
                {t('Open analysis')}
              </Button>
            }
          />
        </Panel>
      ) : (
        <div className="grid min-h-[560px] flex-1 gap-4 lg:grid-cols-[1fr_290px]">
          <Panel className="!p-0">
            <div className="h-[620px] w-full">
              <ReactFlow
                nodes={nodes}
                edges={edges}
                nodeTypes={nodeTypes}
                fitView
                fitViewOptions={{ padding: 0.25 }}
                minZoom={0.25}
                onNodeClick={onNodeClick}
                defaultEdgeOptions={{ deletable: false }}
                nodesConnectable={false}
                proOptions={{ hideAttribution: true }}
              >
                <Background
                  variant={BackgroundVariant.Dots}
                  gap={26}
                  size={1.2}
                  color="#1e293b"
                />
                <Controls />
                <MiniMap
                  nodeColor={(node) => {
                    const kind = (node.data as { node: GraphNode }).node.kind
                    const colors = {
                      root: '#34d399',
                      source: '#2dd4bf',
                      evidence: '#a78bfa',
                      indicator: '#fbbf24',
                    } as const
                    return colors[kind]
                  }}
                />
                <div className="pointer-events-none absolute top-3 left-3 z-10 space-y-1.5 font-mono text-[10px] text-slate-400">
                  <LegendDot color="#34d399" label={t('root indicator')} />
                  <LegendDot color="#2dd4bf" label={t('provider source')} />
                  <LegendDot color="#a78bfa" label={t('evidence item')} />
                  <LegendDot color="#fbbf24" label={t('related IOC')} />
                  <LegendHint>{t('click a node for details')}</LegendHint>
                </div>
              </ReactFlow>
            </div>
          </Panel>

          <Panel
            eyebrow={t('Selected entity')}
            title={selected ? t('Node details') : t('No selection')}
            className="h-fit"
            action={
              selected && isRoot ? (
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => navigate(`/analysis/${analysisId}`)}
                >
                  {t('Open analysis')}
                  <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              ) : undefined
            }
          >
            {!selected ? (
              <p className="text-[12.5px] leading-relaxed text-ink-3">
                {t(
                  'Click any node to inspect its relationship, verdict and raw evidence metadata.',
                )}
              </p>
            ) : (
              <div className="space-y-3">
                <div>
                  <span className="eyebrow">{t(`kind.${selected.kind}`)}</span>
                  <p className="mt-1.5 break-all font-mono text-[12.5px] leading-snug text-ink">
                    {selected.label}
                  </p>
                  {selected.subtitle && (
                    <p className="mt-1 text-[12px] text-ink-2">
                      {selected.subtitle}
                    </p>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  <LevelBadge level={levelOf(selected.verdict)} />
                  {selected.score != null && (
                    <span
                      className={cn(
                        'rounded-md border px-2 py-0.5 font-mono text-[13px] font-semibold tabular-nums',
                        scoreClass(selected.score),
                      )}
                    >
                      {selected.score}
                    </span>
                  )}
                </div>

                {selected.url && (
                  <a
                    href={selected.url}
                    target="_blank"
                    rel="noreferrer"
                    className="focus-ring block truncate text-[12px] text-accent-strong hover:underline"
                  >
                    {selected.url}
                  </a>
                )}

                {Object.keys(selected.meta ?? {}).length > 0 && (
                  <dl className="space-y-1.5 border-t border-border/70 pt-3">
                    {Object.entries(selected.meta ?? {}).map(([key, value]) => {
                      if (value == null || value === '') return null
                      return (
                        <div key={key} className="flex justify-between gap-2">
                          <dt className="text-[11px] text-ink-3 capitalize">
                            {key.replaceAll('_', ' ')}
                          </dt>
                          <dd className="max-w-[55%] truncate text-right font-mono text-[11.5px] text-ink">
                            {String(value)}
                          </dd>
                        </div>
                      )
                    })}
                  </dl>
                )}

                <p className="border-t border-border/70 pt-3 text-[11px] text-ink-3">
                  {t('node id')} {shortId(selected.id)} · {formatDate(graph.data?.generated_at)}
                </p>
              </div>
            )}
          </Panel>
        </div>
      )}
    </div>
  )
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span
        className="h-2.5 w-2.5 rounded-full"
        style={{ backgroundColor: color }}
      />
      {label}
    </div>
  )
}

function LegendHint({ children }: { children: React.ReactNode }) {
  return <div className="pt-1 text-slate-500 italic">{children}</div>
}