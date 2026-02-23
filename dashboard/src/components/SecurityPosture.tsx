'use client'

import { useSecurity } from '@/hooks/useSecurity'

function ensureObject(val: unknown): Record<string, unknown> {
  if (val && typeof val === 'object' && !Array.isArray(val)) return val as Record<string, unknown>
  if (typeof val === 'string') {
    try { return JSON.parse(val) } catch { return {} }
  }
  return {}
}

export function SecurityPosture() {
  const { data, error, isLoading } = useSecurity()

  if (error) {
    return <div className="bg-red-50 text-red-700 rounded-lg p-4">Failed to load security data: {error.message}</div>
  }

  if (isLoading || !data) {
    return <div className="bg-white rounded-lg shadow-sm p-4 text-sm text-slate-400">Loading security posture...</div>
  }

  const bySeverity = ensureObject(data.alerts_by_severity) as { info?: number; warning?: number; critical?: number }
  const bySource = ensureObject(data.alerts_by_source) as Record<string, number>
  const totalAlerts = data.total_alerts ?? 0
  const parity = ensureObject(data.parity) as { mismatches_total?: number }

  return (
    <div className="bg-white rounded-lg shadow-sm">
      <div className="p-4 border-b border-slate-100">
        <h2 className="text-lg font-semibold text-slate-800">Security Posture</h2>
      </div>
      <div className="p-4 space-y-4">
        <div className="text-center">
          <p className="text-3xl font-bold text-slate-800">{totalAlerts}</p>
          <p className="text-sm text-slate-500">Total Alerts</p>
        </div>

        <div className="grid grid-cols-3 gap-2">
          <div className="bg-red-50 rounded-lg p-3 text-center">
            <p className="text-xl font-bold text-red-700">{bySeverity.critical || 0}</p>
            <p className="text-xs text-red-600">Critical</p>
          </div>
          <div className="bg-amber-50 rounded-lg p-3 text-center">
            <p className="text-xl font-bold text-amber-700">{bySeverity.warning || 0}</p>
            <p className="text-xs text-amber-600">Warning</p>
          </div>
          <div className="bg-green-50 rounded-lg p-3 text-center">
            <p className="text-xl font-bold text-green-700">{bySeverity.info || 0}</p>
            <p className="text-xs text-green-600">Info</p>
          </div>
        </div>

        <div>
          <h3 className="text-sm font-medium text-slate-700 mb-2">Alerts by Source</h3>
          <div className="space-y-1">
            {Object.entries(bySource).map(([source, count]) => (
              <div key={source} className="flex items-center justify-between text-sm">
                <span className="text-slate-600">{source}</span>
                <span className="font-medium text-slate-800">{count as number}</span>
              </div>
            ))}
            {Object.keys(bySource).length === 0 && (
              <p className="text-xs text-slate-400">No sources</p>
            )}
          </div>
        </div>

        <div>
          <h3 className="text-sm font-medium text-slate-700 mb-1">Parity</h3>
          {parity.mismatches_total !== undefined && parity.mismatches_total > 0 ? (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-amber-500" />
              <span className="text-sm text-amber-700">{parity.mismatches_total} mismatches</span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-green-500" />
              <span className="text-sm text-green-700">In sync</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
