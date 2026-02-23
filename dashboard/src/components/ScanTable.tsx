'use client'

import { useState } from 'react'
import { useScans } from '@/hooks/useScans'
import { StatusBadge } from './StatusBadge'

type SortField = 'category' | 'status'
type SortDir = 'asc' | 'desc'
type FilterStatus = 'All' | 'Fail' | 'Warn' | 'Pass'

const statusOrder: Record<string, number> = { Fail: 0, Warn: 1, Pass: 2 }

interface Scan {
  category: string
  status: string
  details: string
  timestamp: string
}

export function ScanTable() {
  const { data: scans, error, isLoading } = useScans()
  const [filter, setFilter] = useState<FilterStatus>('All')
  const [sortField, setSortField] = useState<SortField>('category')
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  const items: Scan[] = scans || []

  const counts = {
    Pass: items.filter((s) => s.status === 'Pass').length,
    Warn: items.filter((s) => s.status === 'Warn').length,
    Fail: items.filter((s) => s.status === 'Fail').length,
  }

  const filtered = items.filter((s) => filter === 'All' || s.status === filter)

  const sorted = [...filtered].sort((a, b) => {
    if (sortField === 'category') {
      const cmp = a.category.localeCompare(b.category)
      return sortDir === 'asc' ? cmp : -cmp
    }
    const cmp = (statusOrder[a.status] ?? 3) - (statusOrder[b.status] ?? 3)
    return sortDir === 'asc' ? cmp : -cmp
  })

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDir('asc')
    }
  }

  if (error) {
    return <div className="bg-red-50 text-red-700 rounded-lg p-4">Failed to load scans: {error.message}</div>
  }

  return (
    <div className="bg-white rounded-lg shadow-sm">
      <div className="p-4 border-b border-slate-100">
        <h2 className="text-lg font-semibold text-slate-800 mb-2">Scanner Results</h2>
        <p className="text-sm text-slate-500 mb-3">
          {counts.Pass} Pass, {counts.Warn} Warn, {counts.Fail} Fail out of {items.length} scans
        </p>
        <div className="flex gap-2">
          {((['All', 'Fail', 'Warn', 'Pass'] as FilterStatus[])).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                filter === f
                  ? 'bg-slate-800 text-white'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {isLoading && <div className="p-4 text-sm text-slate-400">Loading scans...</div>}
      {!isLoading && sorted.length === 0 && (
        <div className="p-4 text-sm text-slate-400">No scan results</div>
      )}

      {sorted.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100">
                <th
                  className="text-left p-4 font-medium text-slate-600 cursor-pointer hover:text-slate-800"
                  onClick={() => toggleSort('category')}
                >
                  Category {sortField === 'category' && (sortDir === 'asc' ? '\u2191' : '\u2193')}
                </th>
                <th
                  className="text-left p-4 font-medium text-slate-600 cursor-pointer hover:text-slate-800"
                  onClick={() => toggleSort('status')}
                >
                  Status {sortField === 'status' && (sortDir === 'asc' ? '\u2191' : '\u2193')}
                </th>
                <th className="text-left p-4 font-medium text-slate-600">Details</th>
                <th className="text-left p-4 font-medium text-slate-600">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((scan, i) => (
                <tr key={i} className="border-b border-slate-50 hover:bg-slate-50">
                  <td className="p-4 text-slate-800">{scan.category}</td>
                  <td className="p-4"><StatusBadge status={scan.status} /></td>
                  <td className="p-4 text-slate-600">{scan.details}</td>
                  <td className="p-4 text-slate-400 text-xs">{scan.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}