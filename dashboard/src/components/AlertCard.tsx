'use client'

import { SeverityBadge } from './SeverityBadge'
import { formatTimestamp } from '@/lib/formatTime'

interface Alert {
  ts: string
  severity: string
  source: string
  message: string
}

export function AlertCard({ alert }: { alert: Alert }) {
  return (
    <div className="bg-white rounded-lg p-4 shadow-sm border border-slate-100">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <SeverityBadge severity={alert.severity} />
            <span className="inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-medium bg-slate-100 text-slate-600">
              {alert.source}
            </span>
            <span className="text-xs text-slate-400">{formatTimestamp(alert.ts)}</span>
          </div>
          <p className="text-sm text-slate-700 truncate">{alert.message}</p>
        </div>
      </div>
    </div>
  )
}
