'use client'

import { useState } from 'react'
import { useAlerts } from '@/hooks/useAlerts'
import { AlertCard } from './AlertCard'

const filters = ['All', 'Critical', 'Warning', 'Info'] as const

const filterMap: Record<string, string> = {
  Critical: 'CRIT',
  Warning: 'WARN',
  Info: 'INFO',
}

export function AlertFeed() {
  const { data: alerts, error, isLoading } = useAlerts()
  const [filter, setFilter] = useState<string>('All')

  const allAlerts = (alerts || [])
    .filter((a: { severity: string }) => {
      if (filter === 'All') return true
      return a.severity === filterMap[filter]
    })
    .sort((a: { ts: string }, b: { ts: string }) => {
      return new Date(b.ts).getTime() - new Date(a.ts).getTime()
    })

  if (error) {
    return <div className="bg-red-50 text-red-700 rounded-lg p-4">Failed to load alerts: {error.message}</div>
  }

  return (
    <div className="bg-white rounded-lg shadow-sm">
      <div className="p-4 border-b border-slate-100">
        <h2 className="text-lg font-semibold text-slate-800 mb-3">Alert Feed</h2>
        <div className="flex gap-2">
          {filters.map((f) => (
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
      <div className="p-4 space-y-2 max-h-[600px] overflow-y-auto">
        {isLoading && <p className="text-sm text-slate-400">Loading alerts...</p>}
        {!isLoading && allAlerts.length === 0 && (
          <p className="text-sm text-slate-400">No alerts yet</p>
        )}
        {allAlerts.map((alert: { ts: string; severity: string; source: string; message: string }, i: number) => (
          <AlertCard key={`${alert.ts}-${i}`} alert={alert} />
        ))}
      </div>
    </div>
  )
}
