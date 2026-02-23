'use client'

import { useState } from 'react'
import { ApprovalForm } from '@/components/ApprovalForm'
import { ApprovalStatus } from '@/components/ApprovalStatus'

interface ApprovalEntry {
  id: string
  command: string
}

export default function ApprovalsPage() {
  const [approvals, setApprovals] = useState<ApprovalEntry[]>([])

  const handleNewApproval = (id: string, command: string) => {
    setApprovals((prev) => [{ id, command }, ...prev])
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-800">Approvals</h1>
      <ApprovalForm onSubmit={handleNewApproval} />
      <ApprovalStatus approvals={approvals} />
    </div>
  )
}
