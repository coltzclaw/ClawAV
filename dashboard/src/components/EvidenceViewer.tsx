'use client'

import { useState } from 'react'
import { StatusBadge } from './StatusBadge'
import { deepParseJsonStrings } from '@/lib/fetcher'

interface ControlFinding {
  control_id: string
  control_name: string
  status: string
  alert_count: number
  highest_severity: string
  categories: string[]
}

interface EvidenceBundle {
  generated_at?: string
  clawtower_version?: string
  compliance_report?: {
    framework: string
    period_days: number
    generated_at?: string
    total_alerts: number
    alerts_by_severity?: {
      critical: number
      warning: number
      info: number
    }
    control_findings?: ControlFinding[]
    scanner_summary?: {
      total_scans: number
      pass_count: number
      warn_count: number
      fail_count: number
    }
  }
  scanner_snapshot?: Array<{
    category: string
    status: string
    details: string
    timestamp: string
  }>
  audit_chain_proof?: {
    integrity_verified: boolean
    chain_file?: string | null
    total_entries?: number | null
    verification_error?: string | null
  }
  policy_versions?: {
    policies?: Array<Record<string, unknown>>
    ioc_databases?: Array<Record<string, unknown>>
    active_profile?: string | null
  }
}

const frameworks = [
  { value: 'soc2', label: 'SOC 2' },
  { value: 'nist800-53', label: 'NIST 800-53' },
  { value: 'cis-v8', label: 'CIS Controls v8' },
  { value: 'mitre-attack', label: 'MITRE ATT&CK' },
]

const frameworkNames: Record<string, string> = {
  soc2: 'SOC 2',
  'nist800-53': 'NIST 800-53',
  'cis-v8': 'CIS Controls v8',
  'mitre-attack': 'MITRE ATT&CK',
}

export function EvidenceViewer() {
  const [framework, setFramework] = useState('soc2')
  const [period, setPeriod] = useState(30)
  const [data, setData] = useState<EvidenceBundle | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchEvidence = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`/api/ct/evidence?framework=${framework}&period=${period}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      let json = await res.json()
      // DTU engine wraps in {data: [...], has_more: boolean}
      if (json && typeof json === 'object' && 'data' in json && Array.isArray(json.data)) {
        json = json.data[0] || null
      }
      // Deep-parse any nested JSON strings from DTU SQLite storage
      if (json) {
        json = deepParseJsonStrings(json)
      }
      setData(json as EvidenceBundle)
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  const report = data?.compliance_report
  const audit = data?.audit_chain_proof
  const policy = data?.policy_versions

  return (
    <div className="space-y-4">
      {/* Controls bar */}
      <div className="bg-white rounded-lg shadow-sm p-4">
        <h2 className="text-lg font-semibold text-slate-800 mb-3">Evidence Viewer</h2>
        <div className="flex flex-wrap items-end gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Framework</label>
            <select
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
              className="px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-400"
            >
              {frameworks.map((f) => (
                <option key={f.value} value={f.value}>{f.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Period (days)</label>
            <input
              type="number"
              value={period}
              onChange={(e) => setPeriod(Number(e.target.value))}
              min={1}
              className="w-24 px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-400"
            />
          </div>
          <button
            onClick={fetchEvidence}
            disabled={loading}
            className="px-4 py-2 bg-slate-800 text-white rounded-lg text-sm font-medium hover:bg-slate-700 disabled:opacity-50 transition-colors"
          >
            {loading ? 'Loading...' : 'Generate'}
          </button>
        </div>
        {error && <div className="mt-3 bg-red-50 text-red-700 rounded-lg p-3 text-sm">{error}</div>}
      </div>

      {!data && !loading && !error && (
        <div className="bg-white rounded-lg shadow-sm p-8 text-center text-slate-400">
          Select a framework and click Generate to create an evidence bundle
        </div>
      )}

      {data && !report && !audit && !policy && (
        <div className="bg-white rounded-lg shadow-sm p-8 text-center text-slate-400">
          No evidence data available for this framework and period
        </div>
      )}

      {/* Compliance Report */}
      {report && (
        <div className="bg-white rounded-lg shadow-sm p-4">
          <h3 className="text-lg font-semibold text-slate-800 mb-1">Compliance Report</h3>
          <p className="text-sm text-slate-500 mb-4">{frameworkNames[report.framework] || report.framework} &mdash; {report.period_days} days</p>

          {report.alerts_by_severity && (
            <div className="grid grid-cols-4 gap-2 mb-4">
              <div className="bg-slate-50 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-slate-800">{report.total_alerts}</p>
                <p className="text-xs text-slate-500">Total</p>
              </div>
              <div className="bg-red-50 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-red-700">{report.alerts_by_severity.critical}</p>
                <p className="text-xs text-red-600">Critical</p>
              </div>
              <div className="bg-amber-50 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-amber-700">{report.alerts_by_severity.warning}</p>
                <p className="text-xs text-amber-600">Warning</p>
              </div>
              <div className="bg-green-50 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-green-700">{report.alerts_by_severity.info}</p>
                <p className="text-xs text-green-600">Info</p>
              </div>
            </div>
          )}

          {report.scanner_summary && (
            <div className="grid grid-cols-4 gap-2 mb-4">
              <div className="bg-slate-50 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-slate-800">{report.scanner_summary.total_scans}</p>
                <p className="text-xs text-slate-500">Total Scans</p>
              </div>
              <div className="bg-green-50 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-green-700">{report.scanner_summary.pass_count}</p>
                <p className="text-xs text-green-600">Pass</p>
              </div>
              <div className="bg-amber-50 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-amber-700">{report.scanner_summary.warn_count}</p>
                <p className="text-xs text-amber-600">Warn</p>
              </div>
              <div className="bg-red-50 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-red-700">{report.scanner_summary.fail_count}</p>
                <p className="text-xs text-red-600">Fail</p>
              </div>
            </div>
          )}

          {report.control_findings && report.control_findings.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100">
                    <th className="text-left p-3 font-medium text-slate-600">Control ID</th>
                    <th className="text-left p-3 font-medium text-slate-600">Control Name</th>
                    <th className="text-left p-3 font-medium text-slate-600">Status</th>
                    <th className="text-left p-3 font-medium text-slate-600">Alerts</th>
                    <th className="text-left p-3 font-medium text-slate-600">Severity</th>
                    <th className="text-left p-3 font-medium text-slate-600">Categories</th>
                  </tr>
                </thead>
                <tbody>
                  {report.control_findings.map((cf, i) => (
                    <tr key={i} className="border-b border-slate-50">
                      <td className="p-3 text-slate-800 font-mono text-xs">{cf.control_id}</td>
                      <td className="p-3 text-slate-700">{cf.control_name}</td>
                      <td className="p-3"><StatusBadge status={cf.status} /></td>
                      <td className="p-3 text-slate-600">{cf.alert_count}</td>
                      <td className="p-3 text-slate-600">{cf.highest_severity}</td>
                      <td className="p-3 text-slate-500 text-xs">{Array.isArray(cf.categories) ? cf.categories.join(', ') : String(cf.categories || '')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Audit Chain */}
      {audit && (
        <div className="bg-white rounded-lg shadow-sm p-4">
          <h3 className="text-lg font-semibold text-slate-800 mb-3">Audit Chain Integrity</h3>
          <div className="flex items-center gap-3 mb-3">
            <span className={`inline-flex items-center px-3 py-1 rounded-lg text-sm font-medium ${
              audit.integrity_verified
                ? 'bg-green-50 text-green-700 border border-green-200'
                : 'bg-red-50 text-red-700 border border-red-200'
            }`}>
              {audit.integrity_verified ? 'Verified' : 'Tampered'}
            </span>
          </div>
          <div className="space-y-1 text-sm text-slate-600">
            {audit.chain_file && <p><span className="font-medium">Chain file:</span> {audit.chain_file}</p>}
            {audit.total_entries != null && <p><span className="font-medium">Total entries:</span> {audit.total_entries}</p>}
            {audit.verification_error && (
              <p className="text-red-600"><span className="font-medium">Error:</span> {audit.verification_error}</p>
            )}
          </div>
        </div>
      )}

      {/* Policy Versions */}
      {policy && (
        <div className="bg-white rounded-lg shadow-sm p-4">
          <h3 className="text-lg font-semibold text-slate-800 mb-3">Policy Versions</h3>
          <div className="space-y-3">
            {policy.policies && policy.policies.length > 0 && (
              <div>
                <p className="text-sm font-medium text-slate-700 mb-1">Loaded Policies:</p>
                <ul className="list-disc list-inside text-sm text-slate-600 space-y-0.5">
                  {policy.policies.map((p, i) => (
                    <li key={i}>{(p as any).name || (p as any).file || JSON.stringify(p)}</li>
                  ))}
                </ul>
              </div>
            )}
            {policy.ioc_databases && policy.ioc_databases.length > 0 && (
              <div>
                <p className="text-sm font-medium text-slate-700 mb-1">IOC Databases:</p>
                <ul className="list-disc list-inside text-sm text-slate-600 space-y-0.5">
                  {policy.ioc_databases.map((d, i) => (
                    <li key={i}>{(d as any).name || (d as any).file || JSON.stringify(d)}</li>
                  ))}
                </ul>
              </div>
            )}
            {policy.active_profile && (
              <p className="text-sm text-slate-600">
                <span className="font-medium">Active Agent Profile:</span> {policy.active_profile}
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
