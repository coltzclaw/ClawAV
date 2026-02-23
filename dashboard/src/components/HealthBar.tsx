'use client'

import { useHealth } from '@/hooks/useHealth'
import { useStatus } from '@/hooks/useStatus'
import { formatRelativeTime, formatUptime } from '@/lib/formatTime'

export function HealthBar() {
  const { data: health, error: healthError } = useHealth()
  const { data: status } = useStatus()

  const healthy = health?.healthy
  const version = health?.version || '—'
  const uptime = formatUptime(health?.uptime_seconds)
  const lastAlert = formatRelativeTime(health?.last_alert_age_seconds)

  // modules is already deep-parsed by singleFetcher, but add fallback
  let modules: Record<string, boolean> = {}
  const rawModules = status?.modules
  if (rawModules && typeof rawModules === 'object' && !Array.isArray(rawModules)) {
    modules = rawModules as unknown as Record<string, boolean>
  } else if (typeof rawModules === 'string') {
    try { modules = JSON.parse(rawModules) } catch { /* ignore */ }
  }

  return (
    <div className="bg-white rounded-lg p-4 shadow-sm">
      <div className="flex flex-wrap items-center gap-6">
        <div className="flex items-center gap-2">
          <div className={`w-3 h-3 rounded-full ${healthError ? 'bg-red-500' : healthy ? 'bg-green-500' : 'bg-amber-500'}`} />
          <span className="text-sm font-medium text-slate-700">
            {healthError ? 'Disconnected' : healthy ? 'Healthy' : 'Unhealthy'}
          </span>
        </div>
        <div className="text-sm text-slate-500">
          <span className="font-medium text-slate-700">Version:</span> {version}
        </div>
        <div className="text-sm text-slate-500">
          <span className="font-medium text-slate-700">Uptime:</span> {uptime}
        </div>
        <div className="text-sm text-slate-500">
          <span className="font-medium text-slate-700">Last Alert:</span> {lastAlert}
        </div>
        {Object.keys(modules).length > 0 && (
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium text-slate-700">Modules:</span>
            {Object.entries(modules).map(([name, enabled]) => (
              <div key={name} className="flex items-center gap-1">
                <div className={`w-2 h-2 rounded-full ${enabled ? 'bg-green-500' : 'bg-slate-300'}`} />
                <span className="text-xs text-slate-500">{name}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
