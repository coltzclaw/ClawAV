import useSWR from 'swr'
import { singleFetcher } from '@/lib/fetcher'
import type { StatusResponse } from '@/lib/types'

export function useStatus() {
  return useSWR<StatusResponse>('/api/ct/status', singleFetcher as () => Promise<StatusResponse>, { refreshInterval: 5000 })
}
