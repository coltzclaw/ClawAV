'use client'

const severityStyles: Record<string, string> = {
  CRIT: 'bg-red-600 text-white',
  critical: 'bg-red-600 text-white',
  WARN: 'bg-amber-500 text-white',
  warning: 'bg-amber-500 text-white',
  INFO: 'bg-green-500 text-white',
  info: 'bg-green-500 text-white',
}

export function SeverityBadge({ severity }: { severity: string }) {
  const style = severityStyles[severity] || severityStyles[severity?.toUpperCase()] || 'bg-slate-400 text-white'
  const label = severity?.toUpperCase() || 'UNKNOWN'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-medium ${style}`}>
      {label}
    </span>
  )
}
