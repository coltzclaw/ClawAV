'use client'

import { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { deepParseJsonStrings } from '@/lib/fetcher'

interface Approval {
  id: string
  status: string
  command?: string
  agent?: string
  severity?: string
  resolved_by?: string
  resolved_at?: string
}

const statusStyles: Record<string, string> = {
  pending: 'bg-amber-50 text-amber-700 border border-amber-200',
  approved: 'bg-green-50 text-green-700 border border-green-200',
  denied: 'bg-red-50 text-red-700 border border-red-200',
  timed_out: 'bg-slate-100 text-slate-600 border border-slate-200',
}

interface ApprovalEntry {
  id: string
  command: string
}

export function ApprovalStatus({ approvals: entries }: { approvals: ApprovalEntry[] }) {
  const ids = useMemo(() => entries.map((e) => e.id), [entries])
  const commandMap = useMemo(() => Object.fromEntries(entries.map((e) => [e.id, e.command])), [entries])
  const [approvals, setApprovals] = useState<Record<string, Approval>>({})
  const approvalsRef = useRef(approvals)
  approvalsRef.current = approvals
  const [resolving, setResolving] = useState<string | null>(null)
  const [errors, setErrors] = useState<Record<string, string>>({})

  const pollApproval = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/ct/approvals/${id}`)
      if (res.ok) {
        let data = await res.json()
        // DTU envelope unwrapping
        if (data && typeof data === 'object' && 'data' in data && Array.isArray(data.data)) {
          data = data.data[0] || null
        }
        if (data) {
          data = deepParseJsonStrings(data)
          setApprovals((prev) => ({ ...prev, [id]: data as Approval }))
        }
      }
    } catch {
      // poll failures are transient
    }
  }, [])

  useEffect(() => {
    if (ids.length === 0) return
    ids.forEach(pollApproval)
    const interval = setInterval(() => {
      ids.forEach((id) => {
        const current = approvalsRef.current[id]
        if (!current || current.status === 'pending') {
          pollApproval(id)
        }
      })
    }, 2000)
    return () => clearInterval(interval)
  }, [ids, pollApproval])

  const handleResolve = async (id: string, approved: boolean) => {
    setResolving(id)
    setErrors((prev) => {
      const next = { ...prev }
      delete next[id]
      return next
    })
    try {
      const res = await fetch(`/api/ct/approvals/${id}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          approved,
          by: 'dashboard_user',
          via: 'dashboard',
        }),
      })
      if (res.ok) {
        pollApproval(id)
      } else {
        const body = await res.json().catch(() => null)
        const errMsg = body?.error || body?.detail || `Failed (HTTP ${res.status})`
        setErrors((prev) => ({ ...prev, [id]: errMsg }))
        pollApproval(id)
      }
    } catch {
      setErrors((prev) => ({ ...prev, [id]: 'Network error' }))
    } finally {
      setResolving(null)
    }
  }

  if (ids.length === 0) return null

  return (
    <div className="bg-white rounded-lg shadow-sm p-4 space-y-3">
      <h2 className="text-lg font-semibold text-slate-800">Approval Status</h2>
      {ids.map((id) => {
        const approval = approvals[id]
        const error = errors[id]
        if (!approval) {
          return (
            <div key={id} className="border border-slate-100 rounded-lg p-3 text-sm text-slate-400">
              Loading {id}...
            </div>
          )
        }
        return (
          <div key={id} className="border border-slate-100 rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-mono text-slate-600">{approval.id}</span>
              <span className={`inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-medium ${statusStyles[approval.status] || statusStyles.pending}`}>
                {approval.status}
              </span>
            </div>
            <p className="text-sm text-slate-700 mb-2">{commandMap[id] || approval.command || ''}</p>
            {error && (
              <div className="bg-red-50 text-red-700 rounded-lg p-2 text-xs mb-2">{error}</div>
            )}
            {approval.status === 'pending' && (
              <div className="flex gap-2">
                <button
                  onClick={() => handleResolve(id, true)}
                  disabled={resolving === id}
                  className="px-3 py-1 bg-green-500 text-white rounded-lg text-xs font-medium hover:bg-green-600 disabled:opacity-50"
                >
                  Approve
                </button>
                <button
                  onClick={() => handleResolve(id, false)}
                  disabled={resolving === id}
                  className="px-3 py-1 bg-red-600 text-white rounded-lg text-xs font-medium hover:bg-red-700 disabled:opacity-50"
                >
                  Deny
                </button>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
