import useSWR from 'swr'
import { singleFetcher } from '@/lib/fetcher'
import type { HealthResponse } from '@/lib/types'

export function useHealth() {
  return useSWR<HealthResponse>('/api/ct/health', singleFetcher as () => Promise<HealthResponse>, { refreshInterval: 5000 })
}
