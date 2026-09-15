import { keepPreviousData, useQuery } from '@tanstack/react-query'

import { fetchAnalysis, fetchHealth, fetchHistory } from '../services/api'
import type { HistoryParams } from '../types'

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: fetchHealth,
    retry: 1,
    refetchInterval: 30_000,
    staleTime: 15_000,
  })
}

export function useHistoryPage(params: HistoryParams) {
  return useQuery({
    queryKey: ['history', params],
    queryFn: () => fetchHistory(params),
    placeholderData: keepPreviousData,
  })
}

export function useAnalysis(analysisId: string | undefined) {
  return useQuery({
    queryKey: ['analysis', analysisId],
    queryFn: () => fetchAnalysis(analysisId!),
    enabled: Boolean(analysisId),
  })
}