'use client'

import { useState } from 'react'
import { deepParseJsonStrings } from '@/lib/fetcher'

interface ApprovalFormProps {
  onSubmit: (id: string, command: string) => void
}

export function ApprovalForm({ onSubmit }: ApprovalFormProps) {
  const [command, setCommand] = useState('')
  const [agent, setAgent] = useState('unknown')
  const [context, setContext] = useState('')
  const [severity, setSeverity] = useState('warning')
  const [timeoutSecs, setTimeoutSecs] = useState(300)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/ct/approvals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command,
          agent,
          context: context || undefined,
          severity,
          timeout_secs: timeoutSecs,
          status: 'pending',
        }),
      })
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`)
      }
      let data = await res.json()
      // DTU engine may wrap in {data: [...], has_more: boolean}
      if (data && typeof data === 'object' && 'data' in data && Array.isArray(data.data)) {
        data = data.data[0] || data
      }
      data = deepParseJsonStrings(data)
      onSubmit(data.id, command)
      setCommand('')
      setContext('')
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="bg-white rounded-lg shadow-sm p-4 space-y-4">
      <h2 className="text-lg font-semibold text-slate-800">Submit Approval Request</h2>

      {error && <div className="bg-red-50 text-red-700 rounded-lg p-3 text-sm">{error}</div>}

      <div>
        <label className="block text-sm font-medium text-slate-700 mb-1">Command *</label>
        <input
          type="text"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          required
          className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-400"
          placeholder="e.g., rm -rf /tmp/suspicious"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-700 mb-1">Agent</label>
        <input
          type="text"
          value={agent}
          onChange={(e) => setAgent(e.target.value)}
          className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-400"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-700 mb-1">Context</label>
        <textarea
          value={context}
          onChange={(e) => setContext(e.target.value)}
          rows={3}
          className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-400"
          placeholder="Additional context..."
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">Severity</label>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-400"
          >
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">Timeout (seconds)</label>
          <input
            type="number"
            value={timeoutSecs}
            onChange={(e) => setTimeoutSecs(Number(e.target.value))}
            min={1}
            className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-400"
          />
        </div>
      </div>

      <button
        type="submit"
        disabled={loading || !command}
        className="px-4 py-2 bg-slate-800 text-white rounded-lg text-sm font-medium hover:bg-slate-700 disabled:opacity-50 transition-colors"
      >
        {loading ? 'Submitting...' : 'Submit Request'}
      </button>
    </form>
  )
}
