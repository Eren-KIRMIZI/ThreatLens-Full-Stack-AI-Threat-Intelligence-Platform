import { createBrowserRouter, RouterProvider } from 'react-router-dom'

import { AppLayout } from './components/layout/AppLayout'
import { AnalysisDetail } from './pages/AnalysisDetail'
import { Analyze } from './pages/Analyze'
import { Dashboard } from './pages/Dashboard'
import { GraphPage } from './pages/Graph'
import { HistoryPage } from './pages/History'
import { Hunt } from './pages/Hunt'
import { InvestigationsPage } from './pages/Investigations'
import { InvestigationWorkspacePage } from './pages/InvestigationWorkspacePage'
import { IOCsPage } from './pages/IOCs'
import { MitreMatrix } from './pages/MitreMatrix'
import { Reports } from './pages/Reports'
import { Settings } from './pages/Settings'
import { WatchlistPage } from './pages/Watchlist'

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