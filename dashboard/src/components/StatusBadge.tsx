'use client'

const statusStyles: Record<string, string> = {
  Pass: 'bg-green-50 text-green-700 border border-green-200',
  Warn: 'bg-amber-50 text-amber-700 border border-amber-200',
  Fail: 'bg-red-50 text-red-700 border border-red-200',
  Finding: 'bg-amber-50 text-amber-700 border border-amber-200',
  Critical: 'bg-red-50 text-red-700 border border-red-200',
}

export function StatusBadge({ status }: { status: string }) {
  const style = statusStyles[status] || 'bg-slate-50 text-slate-700 border border-slate-200'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-medium ${style}`}>
      {status}
    </span>
  )
}
