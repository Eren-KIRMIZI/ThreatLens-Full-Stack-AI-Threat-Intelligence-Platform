# ThreatLens Frontend

React 19 + TypeScript single-page app for [ThreatLens](../README.md) — evidence-
first threat intelligence with AI interpretation and PDF reports.

## Stack

- **React 19 + TypeScript** with Vite 8 and @vitejs/plugin-react
- **Tailwind CSS v4** (via @tailwindcss/vite)
- **TanStack Query** — server state, caching, retries
- **React Hook Form + Zod** — indicator forms with client-side validation
- **recharts** — dashboard threat gauges & distribution donut
- **oxlint** — static analysis (see `.oxlintrc.json`)

## Development

```bash
npm install
npm run dev        # http://localhost:5173
```

Vite proxies `/api/*` to `http://127.0.0.1:8000` (see `vite.config.ts`), so the
frontend never holds API keys — everything flows through the FastAPI backend.

## Scripts

| Script | What it does |
| --- | --- |
| `npm run dev` | Vite dev server with HMR + API proxy |
| `npm run build` | `tsc -b` then `vite build` (output in `dist/`) |
| `npm run lint` | oxlint over `src/` |
| `npm run preview` | serve the production build locally |

## Pages & routing

| Route | Page |
| --- | --- |
| `/` | Dashboard — scores: critical/malicious/suspicious/clean distribution, quick analyze |
| `/analyze` | Analyze — hash / URL / domain / IP / file upload, AI toggle |
| `/analysis/:analysisId` | Analysis detail — detections table, metadata, AI interpretation, PDF download |
| `/history` | History — filter by verdict, search, pagination |
| `/reports` | Reports — saved analyses with JSON preview + PDF download |
| `/settings` | Settings — runtime configuration status (keys live server-side) |

## Key files

- `src/services/api.ts` — typed axios client (analysis CRUD, AI enrichment, reports, PDF URL helper)
- `src/types/index.ts` — shared domain types (analysis, detections, `AIAnalysis`, `ReportDocument`)
- `src/hooks/useAnalyses.ts` — TanStack Query hooks (list, detail, analyze, enrich)
- `src/components/analysis/` — `LevelBadge`, `ThreatGauge`, `DetectionBar/Table`, `MetadataView`, `AiAnalysisView`, `AnalysisResultView`
- `src/components/reports/ReportPreview.tsx` — structured report renderer
- `src/utils/validate.ts` — zod schemas & API error mapping

## CI

`npm run lint` and `npm run build` run in CI (`.github/workflows/ci.yml`) on every
push/PR to `main`.

See the [root README](../README.md) for setup, configuration and API docs.