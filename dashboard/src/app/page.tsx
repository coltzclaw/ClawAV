'use client'

import { HealthBar } from '@/components/HealthBar'
import { AlertFeed } from '@/components/AlertFeed'
import { SecurityPosture } from '@/components/SecurityPosture'

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-800">Dashboard</h1>
      <HealthBar />
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <AlertFeed />
        </div>
        <div>
          <SecurityPosture />
        </div>
      </div>
    </div>
  )
}
