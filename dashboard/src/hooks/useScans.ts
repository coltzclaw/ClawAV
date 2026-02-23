import useSWR from 'swr'
import { listFetcher } from '@/lib/fetcher'
import type { ScanResult } from '@/lib/types'

export function useScans() {
  return useSWR<ScanResult[]>('/api/ct/scans', listFetcher as () => Promise<ScanResult[]>, { refreshInterval: 5000 })
}
