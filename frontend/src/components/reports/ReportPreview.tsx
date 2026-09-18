import { Braces, ListChecks, Table2 } from 'lucide-react'

import type { ReportBlock, ReportDocument } from '../../types'
import { useI18n } from '../../i18n'

function FactsBlock({
  facts,
}: {
  facts: NonNullable<ReportBlock['facts']>
}) {
  const { t } = useI18n()
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
      {facts.map((row) => (
        <div key={row.label} className="min-w-0">
          <dt className="eyebrow mb-0.5">{t(row.label)}</dt>
          <dd className="break-words text-[13px] text-ink">{row.value}</dd>
        </div>
      ))}
    </dl>
  )
}

function TableBlock({ block }: { block: ReportBlock }) {
  const { t } = useI18n()
  const table = block.table
  if (!table) return null
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left">
        <thead>
          <tr className="border-b border-border bg-surface">
            {table.columns.map((column) => (
              <th
                key={column}
                className="eyebrow px-4 py-2.5 font-normal"
              >
                {t(column)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {table.rows.map((row, rowIndex) => (
            <tr
              key={rowIndex}
              className="border-b border-border/60 last:border-0 hover:bg-surface-2"
            >
              {row.map((cell, cellIndex) => (
                <td
                  key={`${rowIndex}-${cellIndex}`}
                  className="px-4 py-2.5 align-top text-[12.5px] text-ink-2"
                >
                  <span className="block max-w-[360px] break-words">
                    {cell}
                  </span>
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function BlockIcon({ kind }: { kind: ReportBlock['kind'] }) {
  if (kind === 'table') return <Table2 className="h-3.5 w-3.5" />
  if (kind === 'facts') return <ListChecks className="h-3.5 w-3.5" />
  return <Braces className="h-3.5 w-3.5" />
}

const BLOCK_ORDER: Record<ReportBlock['kind'], string> = {
  paragraph: 'A',
  facts: 'B',
  table: 'C',
}

interface ReportPreviewProps {
  report: ReportDocument
}

export function ReportPreview({ report }: ReportPreviewProps) {
  const { t } = useI18n()
  const blocks = [...report.blocks].sort((a, b) =>
    BLOCK_ORDER[a.kind].localeCompare(BLOCK_ORDER[b.kind]),
  )

  return (
    <div className="space-y-4">
      {blocks.map((block, index) => (
        <section
          key={`${block.heading}-${index}`}
          className="rounded-lg border border-border bg-surface"
        >
          <h4 className="flex items-center gap-2 border-b border-border/60 px-4 py-2.5 text-[13px] font-semibold text-ink">
            <span className="grid h-6 w-6 place-items-center rounded-md bg-surface-3 text-accent">
              <BlockIcon kind={block.kind} />
            </span>
            {t(block.heading)}
          </h4>
          <div className="px-4 py-3.5">
            {block.kind === 'paragraph' && (
              <p className="text-[13.5px] leading-relaxed whitespace-pre-line text-ink-2">
                {block.text}
              </p>
            )}
            {block.kind === 'facts' && (
              <FactsBlock facts={block.facts ?? []} />
            )}
            {block.kind === 'table' && <TableBlock block={block} />}
          </div>
        </section>
      ))}
    </div>
  )
}