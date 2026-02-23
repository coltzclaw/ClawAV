export interface Alert {
  ts: string
  severity: string
  source: string
  message: string
}

export interface HealthResponse {
  healthy: boolean
  uptime_seconds: number
  version: string
  last_alert_age_seconds: number | null
}

export interface Modules {
  auditd: boolean
  network: boolean
  behavior: boolean
  firewall: boolean
}

export interface ParityStatus {
  mismatches_total: number
  alerts_emitted: number
  alerts_suppressed: number
}

export interface StatusResponse {
  status: string
  uptime_seconds: number
  version: string
  modules: Modules
  parity: ParityStatus
}

export interface SeverityCounts {
  info: number
  warning: number
  critical: number
}

export interface SecurityResponse {
  uptime_seconds: number
  total_alerts: number
  alerts_by_severity: SeverityCounts
  alerts_by_source: Record<string, number>
  parity: ParityStatus
}

export interface ScanResult {
  category: string
  status: string
  details: string
  timestamp: string
}

export interface PendingAction {
  id: string
  threat_source: string
  threat_message: string
  severity: string
  mode: string
  actions: string[]
  playbook: string | null
  status: string
  age_seconds: number
}

export interface ApprovalStatus {
  id: string
  status: string
}

export interface EvidenceBundle {
  generated_at: string
  clawtower_version: string
  compliance_report: {
    framework: string
    period_days: number
    generated_at: string
    total_alerts: number
    alerts_by_severity: { critical: number; warning: number; info: number }
    control_findings: {
      control_id: string
      control_name: string
      alert_count: number
      highest_severity: string
      status: string
      categories: string[]
    }[]
    scanner_summary: {
      total_scans: number
      pass_count: number
      warn_count: number
      fail_count: number
    }
  }
  scanner_snapshot: ScanResult[]
  audit_chain_proof: {
    chain_file: string | null
    total_entries: number | null
    integrity_verified: boolean
    verification_error: string | null
  }
  policy_versions: {
    policies: Record<string, unknown>[]
    ioc_databases: Record<string, unknown>[]
    active_profile: string | null
  }
}
