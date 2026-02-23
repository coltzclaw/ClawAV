# ClawTower Security Dashboard — Implementation Plan

## Overview

A Next.js App Router application that proxies the ClawTower REST API and provides a visual security operations console. All state lives in ClawTower (via DTU twin at `http://localhost:9000/twins/clawtower`). No database, no auth. SWR polling at 5-second intervals.

## Architecture

```
Browser --> Next.js (port 3000) --> ClawTower twin (port 9000)
              |                         |
              +- /api/ct/* (proxy)  ----> /api/* (DTU twin)
              +- /* (pages/UI)
```

### Critical Design Decision: Catch-All Proxy

A single catch-all route at `/api/ct/[...path]/route.ts` instead of 14 individual route files. This handles all methods, forwards query params, headers, body, and preserves upstream status codes (404, 405, 501). Every scenario tests through this proxy.

---

## Phase 1: Project Scaffold + Proxy (Scenario-Critical)

All 20 scenarios test the proxy layer at `http://localhost:3000/api/ct/*`. This phase must pass before anything else matters.

### Step 1.1: Project Setup

The Next.js project already exists in `clawtower/`. Verify dependencies:

**Required dependencies:**
```json
{
  "next": "^15.1.0",
  "react": "^19.0.0",
  "react-dom": "^19.0.0",
  "swr": "^2.3.0",
  "tailwindcss": "^4.0.0",
  "@tailwindcss/postcss": "^4.0.0"
}
```

**Environment:** `clawtower/.env.local`
```
CLAWTOWER_API_URL=http://localhost:9000/twins/clawtower
```

### Step 1.2: Catch-All Proxy Route

**File:** `src/app/api/ct/[...path]/route.ts`

```typescript
import { NextRequest } from 'next/server';

const CT_BASE = process.env.CLAWTOWER_API_URL || 'http://localhost:9000/twins/clawtower';

async function proxyRequest(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  const apiPath = path.join('/');
  const url = new URL(`${CT_BASE}/api/${apiPath}`);

  // Forward query params (evidence: ?framework=soc2&period=30)
  request.nextUrl.searchParams.forEach((value, key) => {
    url.searchParams.set(key, value);
  });

  // Forward headers (Content-Type, X-Slack-* for webhooks)
  const headers: Record<string, string> = {};
  for (const [key, value] of request.headers.entries()) {
    const lk = key.toLowerCase();
    if (lk === 'content-type' || lk.startsWith('x-')) {
      headers[key] = value;
    }
  }

  const fetchOptions: RequestInit = { method: request.method, headers };

  // Forward body for non-GET/HEAD (handles JSON and form-urlencoded)
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    fetchOptions.body = await request.text();
  }

  const upstream = await fetch(url.toString(), fetchOptions);

  // Preserve upstream status code and content-type exactly
  const responseHeaders = new Headers();
  const ct = upstream.headers.get('content-type');
  if (ct) responseHeaders.set('content-type', ct);

  const body = await upstream.arrayBuffer();
  return new Response(body, {
    status: upstream.status,
    headers: responseHeaders,
  });
}

export const GET = proxyRequest;
export const POST = proxyRequest;
```

### Step 1.3: Proxy Verification (20 Scenarios)

Every scenario hits `/api/ct/*`. Critical proxy behaviors tested:

| Behavior | Scenarios | Detail |
|----------|-----------|--------|
| Query param forwarding | evidence-soc2, evidence-frameworks, evidence-periods | `?framework=soc2&period=7` |
| Path param forwarding | pending-approve-deny, pending-bulk-actions, approval-workflow, approval-errors, approval-double-resolve | `/pending/pen_001/approve`, `/approvals/{id}/resolve` |
| JSON body forwarding | pending-approve-deny, approval-workflow | `{ "by": "dashboard_user" }` |
| Form-urlencoded body | webhook-hooks | Slack sends `application/x-www-form-urlencoded` |
| Custom header forwarding | webhook-hooks | `X-Slack-Request-Timestamp`, `X-Slack-Signature` |
| Status 200 pass-through | All GET scenarios | Normal responses |
| Status 404 pass-through | approval-errors | Non-existent approval ID |
| Status 405 pass-through | approval-double-resolve | Double-resolve attempt |
| Status 4xx pass-through | pending-resolve-errors | Non-existent pending action |
| Status 501 pass-through | webhook-hooks | Discord webhook → 501 |
| Empty session handling | alerts-empty-state, evidence-empty-state | No fixtures loaded |

---

## Phase 2: Layout + Design System

### Step 2.1: Root Layout

**File:** `src/app/layout.tsx`

- Import Inter font via `next/font/google`
- Apply font class to `<html>`
- Flex layout: fixed sidebar (left) + scrollable main content (right)
- Sidebar: `bg-slate-900`, main: `bg-slate-50`

### Step 2.2: Global Styles

**File:** `src/app/globals.css`

- Tailwind directives (`@import "tailwindcss"` for v4)
- Base font: Inter, 16px
- `body` minimum height: 100vh

### Step 2.3: Sidebar

**File:** `src/components/Sidebar.tsx`

- `bg-slate-900 text-white` full height
- "ClawTower" text/logo at top
- Nav links: Dashboard `/`, Scans `/scans`, Pending `/pending`, Approvals `/approvals`, Evidence `/evidence`
- Active page highlighted via `usePathname()`
- Responsive: collapses to hamburger on mobile

### Step 2.4: Badge Components

**File:** `src/components/SeverityBadge.tsx`
- CRIT → `bg-red-600 text-white` or `bg-red-50 text-red-700`
- WARN → `bg-amber-500 text-white` or `bg-amber-50 text-amber-700`
- INFO → `bg-green-500 text-white` or `bg-green-50 text-green-700`
- `rounded-lg` (0.5rem)

**File:** `src/components/StatusBadge.tsx`
- Pass → green, Warn → amber, Fail → red
- Same styling convention

---

## Phase 3: SWR Hooks + Utilities

### Step 3.1: Fetcher

**File:** `src/lib/fetcher.ts`
```typescript
export const fetcher = (url: string) =>
  fetch(url).then(res => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  });
```

### Step 3.2: Time Formatting

**File:** `src/lib/formatTime.ts`
- `formatRelativeTime(isoString)` → "2m ago", "1h ago"
- `formatUptime(seconds)` → "1d 0h 0m"
- `formatAgeSeconds(seconds)` → "45s ago"

### Step 3.3: SWR Hooks

Six hooks, all following the same pattern:

| File | Endpoint | Refresh |
|------|----------|---------|
| `src/hooks/useHealth.ts` | `/api/ct/health` | 5s |
| `src/hooks/useStatus.ts` | `/api/ct/status` | 5s |
| `src/hooks/useAlerts.ts` | `/api/ct/alerts` | 5s |
| `src/hooks/useSecurity.ts` | `/api/ct/security` | 5s |
| `src/hooks/useScans.ts` | `/api/ct/scans` | 5s |
| `src/hooks/usePending.ts` | `/api/ct/pending` | 5s |

Each returns `{ data, error, isLoading, mutate }`.

---

## Phase 4: Dashboard Home (`/`)

**File:** `src/app/page.tsx`

Three-section layout:

### Section 1: Health Status Bar

**Component:** `src/components/HealthBar.tsx`

Uses `useHealth()` + `useStatus()`.

- Connection: green dot "Healthy" / red dot "Unhealthy" (from `healthy` boolean)
- Version: `version` string (e.g. "0.5.7-beta")
- Uptime: format `uptime_seconds` (86400 → "1d 0h 0m")
- Last alert: format `last_alert_age_seconds` or "No alerts" if null
- Active modules: auditd, network, behavior, firewall — green dot if true in `modules` object

**Fixture data shape:**
```json
{ "healthy": true, "uptime_seconds": 86400, "version": "0.5.7-beta", "last_alert_age_seconds": 120 }
```

### Section 2: Alert Feed

**Component:** `src/components/AlertFeed.tsx` + `src/components/AlertCard.tsx`

Uses `useAlerts()`.

- Filter buttons: All / Critical / Warning / Info (client-side filter)
- Scrollable list, newest-first (sort by `ts` descending)
- Each card: relative timestamp, SeverityBadge, source module badge, message
- Empty state: "No alerts yet"

**Fixture alert shape:**
```json
{ "ts": "2026-02-22T10:00:00Z", "severity": "CRIT", "source": "behavior", "message": "..." }
```

Severity values: `CRIT`, `WARN`, `INFO`

### Section 3: Security Posture Panel

**Component:** `src/components/SecurityPosture.tsx`

Uses `useSecurity()`.

- Three severity counters: Critical (red), Warning (amber), Info (green) from `alerts_by_severity`
- Alerts by source: list from `alerts_by_source` (e.g. behavior: 2, auditd: 2, ...)
- Total alerts counter from `total_alerts`
- Parity: mismatch counter from `parity.mismatches_total`, warning if > 0

**Fixture data shape:**
```json
{
  "total_alerts": 8,
  "alerts_by_severity": { "info": 2, "warning": 3, "critical": 3 },
  "alerts_by_source": { "behavior": 2, "auditd": 2, "sentinel": 1, ... },
  "parity": { "mismatches_total": 2, "alerts_emitted": 2, "alerts_suppressed": 0 }
}
```

---

## Phase 5: Scanner Results (`/scans`)

**File:** `src/app/scans/page.tsx`
**Component:** `src/components/ScanTable.tsx`

Uses `useScans()`.

- Summary: "X Pass, Y Warn, Z Fail out of N scans"
- Filter buttons: All / Fail / Warn / Pass
- Table: Category, Status (badge), Details, Timestamp
- Sortable: Category (alpha), Status (Fail > Warn > Pass)
- Empty state: "No scan results"

**Fixture has 8 scans:** firewall(Fail), suid_sgid(Pass), auditd(Pass), docker_security(Warn), kernel_modules(Pass), world_writable(Warn), ssh_config(Pass), process_health(Pass)

---

## Phase 6: Pending Actions (`/pending`)

**File:** `src/app/pending/page.tsx`
**Component:** `src/components/PendingActionCard.tsx`

Uses `usePending()`.

Each card:
- Threat source + SeverityBadge (CRIT/WARN/INFO)
- Threat message
- Mode badge: "Gate" (blue-500) or "Reactive" (purple-500)
- Actions list (bullet points): e.g. "kill_process(pid=4821)", "lock_clawsudo"
- Playbook name
- Age timer: format `age_seconds`
- **Approve** (green) → `POST /api/ct/pending/{id}/approve` body `{ "by": "dashboard_user" }`
- **Deny** (red) → `POST /api/ct/pending/{id}/deny` body `{ "by": "dashboard_user" }`
- After action: show resolution text, disable buttons, call `mutate()` to refresh

**Fixture has 3 pending actions:** pen_001 (CRIT, Gate), pen_002 (WARN, Reactive), pen_003 (CRIT, Reactive)

---

## Phase 7: Approvals (`/approvals`)

**File:** `src/app/approvals/page.tsx`

### Section 1: Submit Form

**Component:** `src/components/ApprovalForm.tsx`

Fields:
- Command (required text)
- Agent name (text, default "unknown")
- Context (textarea)
- Severity (dropdown: info/warning/critical, default "warning")
- Timeout seconds (number, default 300)
- Submit → `POST /api/ct/approvals` with JSON body

On success: show returned `id`, begin polling.

**Request body shape:**
```json
{
  "command": "sudo systemctl restart nginx",
  "agent": "openclaw",
  "context": "Restarting nginx after config update",
  "severity": "warning",
  "timeout_secs": 300
}
```

### Section 2: Approval Status

**Component:** `src/components/ApprovalStatus.tsx`

- Polls `GET /api/ct/approvals/{id}` every 2 seconds while status is "pending"
- Status badge: pending (yellow), approved (green), denied (red), timed_out (gray)
- For pending items: Approve / Deny buttons
  - Approve: `POST /api/ct/approvals/{id}/resolve` body `{ "approved": true, "by": "dashboard_user", "via": "dashboard" }`
  - Deny: same with `"approved": false`
- Handle 405 on double-resolve gracefully (show warning, don't crash)

**Status values:** `pending`, `approved`, `denied`, `timed_out`

---

## Phase 8: Evidence (`/evidence`)

**File:** `src/app/evidence/page.tsx`
**Component:** `src/components/EvidenceViewer.tsx`

### Controls Bar
- Framework dropdown: SOC 2 (`soc2`), NIST 800-53 (`nist800-53`), CIS Controls v8 (`cis-v8`), MITRE ATT&CK (`mitre-attack`)
- Period input (number, default 30)
- Generate button → `GET /api/ct/evidence?framework={fw}&period={days}`

### Compliance Report
- Framework name + period
- Alert summary: total, critical, warning, info
- Scanner summary: total_scans, pass_count, warn_count, fail_count
- Control Findings table: control_id, control_name, status badge (Pass/Finding/Critical), alert_count, highest_severity, categories

### Audit Chain Integrity
- "Verified" (green) or "Tampered" (red) badge from `integrity_verified`
- Chain file path, total entries
- Verification error if present

### Policy Versions
- Policies list (name, version, loaded_at)
- IOC databases list (name, entries, updated_at)
- Active profile

**Evidence bundle shape (key sections):**
```json
{
  "generated_at": "...",
  "clawtower_version": "0.5.7-beta",
  "compliance_report": {
    "framework": "soc2",
    "period_days": 30,
    "total_alerts": 8,
    "alerts_by_severity": { "critical": 3, "warning": 3, "info": 2 },
    "control_findings": [{ "control_id": "CC6.1", "status": "Critical", ... }],
    "scanner_summary": { "total_scans": 8, "pass_count": 5, "warn_count": 2, "fail_count": 1 }
  },
  "scanner_snapshot": [...],
  "audit_chain_proof": { "integrity_verified": true, "chain_file": "...", "total_entries": 1247 },
  "policy_versions": { "policies": [...], "ioc_databases": [...], "active_profile": "openclaw-restricted" }
}
```

---

## Phase 9: Error & Empty States

Across all pages:
- **Loading:** Skeleton/spinner while SWR fetches
- **Error:** Red banner with error message
- **Empty states:**
  - Alerts: "No alerts yet"
  - Scans: "No scan results"
  - Pending: "No pending actions"
  - Evidence: render empty report structure gracefully (zero counts)

---

## Complete File Tree

```
clawtower/
  .env.local                              # CLAWTOWER_API_URL
  package.json
  tsconfig.json
  next.config.ts
  postcss.config.mjs
  src/
    app/
      layout.tsx                          # Root layout + Inter font + sidebar
      page.tsx                            # Dashboard home
      globals.css                         # Tailwind + base styles
      scans/page.tsx
      pending/page.tsx
      approvals/page.tsx
      evidence/page.tsx
      api/ct/[...path]/route.ts           # Catch-all proxy → ClawTower
    components/
      Sidebar.tsx
      HealthBar.tsx
      AlertCard.tsx
      AlertFeed.tsx
      SecurityPosture.tsx
      ScanTable.tsx
      PendingActionCard.tsx
      ApprovalForm.tsx
      ApprovalStatus.tsx
      EvidenceViewer.tsx
      SeverityBadge.tsx
      StatusBadge.tsx
    hooks/
      useHealth.ts
      useStatus.ts
      useAlerts.ts
      useSecurity.ts
      useScans.ts
      usePending.ts
    lib/
      fetcher.ts
      formatTime.ts
```

**Totals:** 1 proxy route (catch-all), 12 components, 6 hooks, 2 lib utilities, 5 pages, 1 layout.

---

## Scenario Coverage Matrix

| Scenario | Routes Tested | Key Assertions |
|----------|--------------|----------------|
| `health-status` | health, status | healthy=true, modules.auditd/network/behavior/firewall exist, parity exists |
| `health-last-alert-age` | health | last_alert_age_seconds exists (non-null with fixtures), version exists |
| `alerts-feed` | alerts, security | body[0].ts/severity/source/message exist, length≥3, severity breakdown |
| `alerts-empty-state` | alerts, security, health | 200 on all, healthy=true, alerts_by_severity exists |
| `scanner-results` | scans | body[0].category/status/details/timestamp exist, length≥6 |
| `security-alert-correlation` | alerts, security | total_alerts≥1, alerts_by_source exists |
| `pending-list` | pending | length≥3, full structure including playbook |
| `pending-approve-deny` | pending, pending/{id}/approve, pending/{id}/deny | result=approved, result=denied |
| `pending-bulk-actions` | pending, pending/{id}/approve, pending/{id}/deny | 3 sequential resolves, mixed |
| `pending-resolve-errors` | pending/{id}/approve, pending/{id}/deny, pending | 4xx for nonexistent, list intact |
| `approval-workflow` | approvals POST, approvals/{id} GET, approvals/{id}/resolve POST | submit→pending→approve→approved |
| `approval-errors` | approvals/{id} GET, approvals POST, approvals/{id}/resolve | 404 for missing, deny works |
| `approval-double-resolve` | approvals, approvals/{id}/resolve, approvals/{id} | second resolve→405, status preserved |
| `approval-timeout` | approvals POST, approvals/{id} GET | timeout_secs=1, sleep 3s, status=timed_out |
| `evidence-soc2` | evidence?framework=soc2 | all 4 bundle sections exist, framework=soc2 |
| `evidence-frameworks` | evidence?framework=nist800-53/cis-v8/mitre-attack | framework matches param |
| `evidence-periods` | evidence?framework=soc2&period=7/90 | period_days matches param |
| `evidence-empty-state` | evidence?framework=soc2 (no fixtures) | valid structure with empty data |
| `dashboard-polling-cycle` | health, alerts, security, scans, pending, status | all 6 succeed, healthy=true, status=running |
| `webhook-hooks` | hooks/slack, hooks/discord | Slack→200 (form-urlencoded + X-Slack headers), Discord→501 |

---

## Implementation Priority

1. **Proxy route** — all 20 scenarios depend on this
2. **Project build verification** — `npm run build` must succeed
3. **Layout + sidebar** — structural shell
4. **SWR hooks + utilities** — shared data layer
5. **Dashboard home** — health bar, alert feed, security posture
6. **Scans page** — table with sort/filter
7. **Pending page** — cards with approve/deny
8. **Approvals page** — form + polling
9. **Evidence page** — framework selector + report
10. **Polish** — error/empty states, loading skeletons, responsive

---

## Risk Notes

1. **Next.js async params**: Route handler `params` must be `await`ed (Next.js 15+ change). Forgetting causes runtime errors.
2. **Body forwarding for webhooks**: Slack sends `application/x-www-form-urlencoded` — proxy must use `request.text()`, not `request.json()`.
3. **Status code pass-through**: `fetch()` doesn't throw on 4xx/5xx — must forward `upstream.status` directly. Wrapping in try/catch that returns 500 would break error scenarios.
4. **Evidence query params**: `url.search` includes the `?` — construct URL properly to avoid double `?`.
5. **SWR mutate after POST**: After approve/deny, call `mutate('/api/ct/pending')` to refresh the list immediately rather than waiting for next poll.
6. **Tailwind v4**: Uses `@import "tailwindcss"` instead of `@tailwind base/components/utilities` directives.
7. **CORS**: Not an issue — browser requests go to Next.js same-origin, which proxies server-side to ClawTower.
