import useSWR from 'swr'
import { singleFetcher } from '@/lib/fetcher'
import type { SecurityResponse } from '@/lib/types'

export function useSecurity() {
  return useSWR<SecurityResponse>('/api/ct/security', singleFetcher as () => Promise<SecurityResponse>, { refreshInterval: 5000 })
}
