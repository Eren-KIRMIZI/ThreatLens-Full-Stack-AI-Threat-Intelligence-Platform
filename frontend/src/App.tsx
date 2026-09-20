import { lazy } from 'react'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'

import { AppLayout } from './components/layout/AppLayout'

const Dashboard = lazy(() => import('./pages/Dashboard').then((m) => ({ default: m.Dashboard })))
const Analyze = lazy(() => import('./pages/Analyze').then((m) => ({ default: m.Analyze })))
const AnalysisDetail = lazy(() =>
  import('./pages/AnalysisDetail').then((m) => ({ default: m.AnalysisDetail })),
)
const GraphPage = lazy(() => import('./pages/Graph').then((m) => ({ default: m.GraphPage })))
const Hunt = lazy(() => import('./pages/Hunt').then((m) => ({ default: m.Hunt })))
const Forensics = lazy(() => import('./pages/Forensics').then((m) => ({ default: m.Forensics })))
const MitreMatrix = lazy(() =>
  import('./pages/MitreMatrix').then((m) => ({ default: m.MitreMatrix })),
)
const HistoryPage = lazy(() => import('./pages/History').then((m) => ({ default: m.HistoryPage })))
const IOCsPage = lazy(() => import('./pages/IOCs').then((m) => ({ default: m.IOCsPage })))
const InvestigationsPage = lazy(() =>
  import('./pages/Investigations').then((m) => ({ default: m.InvestigationsPage })),
)
const InvestigationWorkspacePage = lazy(() =>
  import('./pages/InvestigationWorkspacePage').then((m) => ({ default: m.InvestigationWorkspacePage })),
)
const WatchlistPage = lazy(() =>
  import('./pages/Watchlist').then((m) => ({ default: m.WatchlistPage })),
)
const Reports = lazy(() => import('./pages/Reports').then((m) => ({ default: m.Reports })))
const Settings = lazy(() => import('./pages/Settings').then((m) => ({ default: m.Settings })))

const router = createBrowserRouter([
  {
    path: '/',
    element: <AppLayout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'analyze', element: <Analyze /> },
      { path: 'analysis/:analysisId', element: <AnalysisDetail /> },
      { path: 'analysis/:analysisId/graph', element: <GraphPage /> },
      { path: 'hunt', element: <Hunt /> },
      { path: 'forensics', element: <Forensics /> },
      { path: 'mitre', element: <MitreMatrix /> },
      { path: 'history', element: <HistoryPage /> },
      { path: 'iocs', element: <IOCsPage /> },
      { path: 'investigations', element: <InvestigationsPage /> },
      { path: 'investigations/:caseId/workspace', element: <InvestigationWorkspacePage /> },
      { path: 'watchlist', element: <WatchlistPage /> },
      { path: 'reports', element: <Reports /> },
      { path: 'settings', element: <Settings /> },
    ],
  },
])

export default function App() {
  return <RouterProvider router={router} />
}