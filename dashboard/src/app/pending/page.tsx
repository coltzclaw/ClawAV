'use client'

import { usePending } from '@/hooks/usePending'
import { PendingActionCard } from '@/components/PendingActionCard'

export default function PendingPage() {
  const { data: actions, error, isLoading, mutate } = usePending()

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-800">Pending Actions</h1>

      {error && (
        <div className="bg-red-50 text-red-700 rounded-lg p-4">
          Failed to load pending actions: {error.message}
        </div>
      )}

      {isLoading && <p className="text-sm text-slate-400">Loading pending actions...</p>}

      {!isLoading && (!actions || actions.length === 0) && (
        <div className="bg-white rounded-lg shadow-sm p-8 text-center text-slate-400">
          No pending actions
        </div>
      )}

      <div className="space-y-4">
        {(actions || []).map((action: any) => (
          <PendingActionCard
            key={action.id}
            action={action}
            onMutate={() => mutate()}
          />
        ))}
      </div>
    </div>
  )
}
