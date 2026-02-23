import useSWR from 'swr'
import { listFetcher } from '@/lib/fetcher'
import type { Alert } from '@/lib/types'

export function useAlerts() {
  return useSWR<Alert[]>('/api/ct/alerts', listFetcher as () => Promise<Alert[]>, { refreshInterval: 5000 })
}
