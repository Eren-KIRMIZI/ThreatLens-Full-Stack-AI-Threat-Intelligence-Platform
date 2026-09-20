import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import {
  addCampaignEvidence,
  addInvestigationItem,
  addInvestigationNote,
  addNote,
  addTag,
  addWatchlistItem,
  createCampaign,
  createInvestigation,
  deleteCampaign,
  deleteCampaignEvidence,
  deleteInvestigation,
  deleteInvestigationNote,
  deleteRule,
  fetchAlerts,
  fetchCampaigns,
  fetchDigest,
  fetchIOC,
  fetchIOCs,
  fetchInvestigation,
  fetchInvestigationNotes,
  fetchInvestigations,
  fetchMitreAnalysis,
  fetchMitreCatalog,
  fetchNotes,
  fetchPinned,
  fetchProviderHealth,
  fetchRules,
  fetchTags,
  fetchWatchlist,
  globalSearch,
  markAlertsSeen,
  removeWatchlistItem,
  rescanAll,
  rescanOne,
  setPinned,
  setWatchlistEnabled,
  updateCampaign,
  updateCampaignEvidence,
  updateInvestigation,
  upsertRule,
} from '../services/api'
import type { IOCParams } from '../types'

// --- IOC registry ------------------------------------------------------------- //

export function useIOCs(params: IOCParams) {
  return useQuery({
    queryKey: ['iocs', params],
    queryFn: () => fetchIOCs(params),
    placeholderData: keepPreviousData,
  })
}

export function useIOC(value: string | undefined) {
  return useQuery({
    queryKey: ['ioc', value],
    queryFn: () => fetchIOC(value!),
    enabled: Boolean(value),
  })
}

export function useProviderHealth(sinceHours = 24) {
  return useQuery({
    queryKey: ['provider-health', sinceHours],
    queryFn: () => fetchProviderHealth(sinceHours),
    staleTime: 30_000,
  })
}

// --- Digest & search ---------------------------------------------------------- //

export function useDigest(window = 'week') {
  return useQuery({
    queryKey: ['digest', window],
    queryFn: () => fetchDigest(window),
    staleTime: 60_000,
  })
}

export function useGlobalSearch(query: string) {
  return useQuery({
    queryKey: ['search', query],
    queryFn: () => globalSearch(query),
    enabled: query.trim().length >= 2,
    placeholderData: keepPreviousData,
  })
}

// --- MITRE ATT&CK ------------------------------------------------------------ //

export function useMitreCatalog() {
  return useQuery({
    queryKey: ['mitre-catalog'],
    queryFn: fetchMitreCatalog,
    staleTime: 10 * 60_000,
  })
}

export function useMitreAnalysis(analysisId: string | undefined) {
  return useQuery({
    queryKey: ['mitre-analysis', analysisId],
    queryFn: () => fetchMitreAnalysis(analysisId!),
    enabled: Boolean(analysisId),
  })
}

// --- Investigations ----------------------------------------------------------- //

export function useInvestigations(params?: { status?: string }) {
  return useQuery({
    queryKey: ['investigations', params],
    queryFn: () => fetchInvestigations({ limit: 100, ...params }),
    placeholderData: keepPreviousData,
  })
}

export function useInvestigation(id: string | undefined) {
  return useQuery({
    queryKey: ['investigation', id],
    queryFn: () => fetchInvestigation(id!),
    enabled: Boolean(id),
  })
}

export function useCreateInvestigation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: createInvestigation,
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['investigations'] }),
  })
}

export function useUpdateInvestigation(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: Parameters<typeof updateInvestigation>[1]) =>
      updateInvestigation(id, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['investigation', id] })
      void queryClient.invalidateQueries({ queryKey: ['investigations'] })
    },
  })
}

export function useDeleteInvestigation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: deleteInvestigation,
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['investigations'] }),
  })
}

export function useAddInvestigationItem(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { value: string; primary_type?: string; analysis_id?: string }) =>
      addInvestigationItem(id, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['investigation', id] })
      void queryClient.invalidateQueries({ queryKey: ['investigations'] })
    },
  })
}

// --- Investigation workspace (notes / campaigns / evidence) ------------------- //

export function useInvestigationNotes(investigationId: string | undefined) {
  return useQuery({
    queryKey: ['case-notes', investigationId],
    queryFn: () => fetchInvestigationNotes(investigationId!),
    enabled: Boolean(investigationId),
  })
}

export function useAddInvestigationNote(investigationId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { author: string; body: string }) =>
      addInvestigationNote(investigationId, body),
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: ['case-notes', investigationId],
      }),
  })
}

export function useDeleteInvestigationNote() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: deleteInvestigationNote,
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['case-notes'] }),
  })
}

export function useCampaigns(investigationId: string | undefined) {
  return useQuery({
    queryKey: ['campaigns', investigationId],
    queryFn: () => fetchCampaigns(investigationId!),
    enabled: Boolean(investigationId),
  })
}

export function useCreateCampaign(investigationId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { name: string; color: string }) =>
      createCampaign(investigationId, body),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['campaigns', investigationId] }),
  })
}

export function useUpdateCampaign(investigationId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (args: { campaignId: string; body: { name?: string; color?: string } }) =>
      updateCampaign(args.campaignId, args.body),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['campaigns', investigationId] }),
  })
}

export function useDeleteCampaign(investigationId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: deleteCampaign,
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['campaigns', investigationId] }),
  })
}

export function useAddCampaignEvidence(investigationId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (
      args: {
        campaignId: string
        body: {
          analysis_id?: string | null
          value: string
          primary_type: string
          note?: string | null
        }
      },
    ) => addCampaignEvidence(args.campaignId, args.body),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['campaigns', investigationId] }),
  })
}

export function useUpdateCampaignEvidence(investigationId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (
      args: {
        campaignId: string
        evidenceId: string
        body: { note?: string | null }
      },
    ) => updateCampaignEvidence(args.campaignId, args.evidenceId, args.body),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['campaigns', investigationId] }),
  })
}

export function useDeleteCampaignEvidence(investigationId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (
      args: { campaignId: string; evidenceId: string },
    ) => deleteCampaignEvidence(args.campaignId, args.evidenceId),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['campaigns', investigationId] }),
  })
}

// --- Analyst workflow (notes / tags / pin) ------------------------------------ //

export function useNotes(analysisId: string | undefined) {
  return useQuery({
    queryKey: ['notes', analysisId],
    queryFn: () => fetchNotes(analysisId!),
    enabled: Boolean(analysisId),
  })
}

export function useAddNote(analysisId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { author: string; body: string }) => addNote(analysisId, body),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['notes', analysisId] }),
  })
}

export function useTags(analysisId: string | undefined) {
  return useQuery({
    queryKey: ['tags', analysisId],
    queryFn: () => fetchTags(analysisId!),
    enabled: Boolean(analysisId),
  })
}

export function useAddTag(analysisId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (tag: string) => addTag(analysisId, tag),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['tags', analysisId] }),
  })
}

export function usePinned() {
  return useQuery({
    queryKey: ['pinned'],
    queryFn: fetchPinned,
    staleTime: 30_000,
  })
}

export function useSetPinned(analysisId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (pinned: boolean) => setPinned(analysisId, pinned),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['pinned'] }),
  })
}

// --- Watchlist & alerts ------------------------------------------------------- //

export function useWatchlist(enabledOnly = false) {
  return useQuery({
    queryKey: ['watchlist', enabledOnly],
    queryFn: () => fetchWatchlist({ enabled_only: enabledOnly, limit: 200 }),
  })
}

export function useAddWatchlistItem() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: addWatchlistItem,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['watchlist'] }),
  })
}

export function useRemoveWatchlistItem() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: removeWatchlistItem,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['watchlist'] }),
  })
}

export function useSetWatchlistEnabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (vars: { id: string; enabled: boolean }) =>
      setWatchlistEnabled(vars.id, vars.enabled),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['watchlist'] }),
  })
}

export function useRules() {
  return useQuery({ queryKey: ['rules'], queryFn: fetchRules })
}

export function useUpsertRule() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: upsertRule,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useDeleteRule() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: deleteRule,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useAlerts(unseenOnly = false) {
  return useQuery({
    queryKey: ['alerts', unseenOnly],
    queryFn: () => fetchAlerts({ unseen_only: unseenOnly, limit: 100 }),
    refetchInterval: 60_000,
  })
}

export function useMarkAlertsSeen() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: markAlertsSeen,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['alerts'] }),
  })
}

export function useRescanAll() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: rescanAll,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['watchlist'] })
      void queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })
}

export function useRescanOne() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: rescanOne,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['watchlist'] })
      void queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })
}