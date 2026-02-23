'use client'

import { ScanTable } from '@/components/ScanTable'

export default function ScansPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-800">Scanner Results</h1>
      <ScanTable />
    </div>
  )
}
