import { useParams } from 'react-router-dom'

import InvestigationWorkspace from '../components/investigation/InvestigationWorkspace'

export function InvestigationWorkspacePage() {
  const { caseId } = useParams<{ caseId: string }>()

  if (!caseId) return null

  return <InvestigationWorkspace caseId={caseId} />
}