'use client'

import { useState } from 'react'
import { SeverityBadge } from './SeverityBadge'
import { formatRelativeTime } from '@/lib/formatTime'

interface PendingAction {
  id: string
  threat_source: string
  threat_message: string
  severity: string
  mode: string
  actions: string[] | string
  playbook?: string | null
  status: string
  age_seconds: number
}

export function PendingActionCard({
  action,
  onMutate,
}: {
  action: PendingAction
  onMutate: () => void
}) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [resolved, setResolved] = useState<string | null>(
    action.status !== 'pending' ? action.status : null
  )

  // Defensive: ensure actions is an array even if DTU returns a string
  let actionsList: string[] = []
  if (Array.isArray(action.actions)) {
    actionsList = action.actions
  } else if (typeof action.actions === 'string') {
    try {
      const parsed = JSON.parse(action.actions)
      actionsList = Array.isArray(parsed) ? parsed : []
    } catch {
      actionsList = action.actions ? [action.actions] : []
    }
  }

  const handleAction = async (type: 'approve' | 'deny') => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`/api/ct/pending/${action.id}/${type}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ by: 'dashboard_user' }),
      })
      if (res.ok) {
        setResolved(type === 'approve' ? 'approved' : 'denied')
        onMutate()
      } else {
        const body = await res.json().catch(() => null)
        setError(body?.error || body?.detail || `Action failed (HTTP ${res.status})`)
      }
    } catch {
      setError('Network error')
    } finally {
      setLoading(false)
    }
  }

  const modeStyle = action.mode === 'Gate'
    ? 'bg-blue-50 text-blue-700 border border-blue-200'
    : 'bg-purple-50 text-purple-700 border border-purple-200'

  return (
    <div className="bg-white rounded-lg shadow-sm p-4 border border-slate-100">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={action.severity} />
          <span className="text-sm font-medium text-slate-700">{action.threat_source}</span>
          <span className={`inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-medium ${modeStyle}`}>
            {action.mode === 'Gate' ? 'Gate' : 'Reactive'}
          </span>
        </div>
        <span className="text-xs text-slate-400">{formatRelativeTime(action.age_seconds)}</span>
      </div>

      <p className="text-sm text-slate-700 mb-3">{action.threat_message}</p>

      {actionsList.length > 0 && (
        <div className="mb-3">
          <p className="text-xs font-medium text-slate-500 mb-1">Proposed Actions:</p>
          <ul className="list-disc list-inside text-sm text-slate-600 space-y-0.5">
            {actionsList.map((a, i) => (
              <li key={i} className="text-xs">{a}</li>
            ))}
          </ul>
        </div>
      )}

      {action.playbook && (
        <p className="text-xs text-slate-500 mb-3">
          <span className="font-medium">Playbook:</span> {action.playbook}
        </p>
      )}

      {error && (
        <p className="text-sm text-red-600 mb-2">{error}</p>
      )}

      {resolved ? (
        <div className={`inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-medium ${
          resolved === 'approved'
            ? 'bg-green-50 text-green-700'
            : 'bg-red-50 text-red-700'
        }`}>
          {resolved === 'approved' ? 'Approved' : 'Denied'}
        </div>
      ) : (
        <div className="flex gap-2">
          <button
            onClick={() => handleAction('approve')}
            disabled={loading}
            className="px-4 py-1.5 bg-green-500 text-white rounded-lg text-xs font-medium hover:bg-green-600 disabled:opacity-50 transition-colors"
          >
            Approve
          </button>
          <button
            onClick={() => handleAction('deny')}
            disabled={loading}
            className="px-4 py-1.5 bg-red-600 text-white rounded-lg text-xs font-medium hover:bg-red-700 disabled:opacity-50 transition-colors"
          >
            Deny
          </button>
        </div>
      )}
    </div>
  )
}
