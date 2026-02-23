import useSWR from 'swr'
import { listFetcher } from '@/lib/fetcher'
import type { PendingAction } from '@/lib/types'

export function usePending() {
  return useSWR<PendingAction[]>('/api/ct/pending', listFetcher as () => Promise<PendingAction[]>, { refreshInterval: 5000 })
}
