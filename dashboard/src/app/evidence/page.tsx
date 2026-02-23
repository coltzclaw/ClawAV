'use client'

import { EvidenceViewer } from '@/components/EvidenceViewer'

export default function EvidencePage() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-800">Compliance Evidence</h1>
      <EvidenceViewer />
    </div>
  )
}
