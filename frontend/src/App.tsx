import { createBrowserRouter, RouterProvider } from 'react-router-dom'

import { AppLayout } from './components/layout/AppLayout'
import { AnalysisDetail } from './pages/AnalysisDetail'
import { Analyze } from './pages/Analyze'
import { Dashboard } from './pages/Dashboard'
import { HistoryPage } from './pages/History'
import { Reports } from './pages/Reports'
import { Settings } from './pages/Settings'

const router = createBrowserRouter([
  {
    path: '/',
    element: <AppLayout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'analyze', element: <Analyze /> },
      { path: 'analysis/:analysisId', element: <AnalysisDetail /> },
      { path: 'history', element: <HistoryPage /> },
      { path: 'reports', element: <Reports /> },
      { path: 'settings', element: <Settings /> },
    ],
  },
])

export default function App() {
  return <RouterProvider router={router} />
}