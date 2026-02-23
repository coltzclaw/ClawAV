# ClawTower Security Dashboard

## Overview

A security operations dashboard that connects to a ClawTower instance's REST API and provides real-time visibility into host security posture, alerts, scanner results, containment actions, approval workflows, and compliance evidence.

ClawTower is a tamper-proof, OS-level security watchdog for AI agents. This dashboard is a read/write frontend for its HTTP REST API.

## Tech Stack

- **Next.js 16** with App Router
- **React 19**
- **Tailwind CSS** for styling
- **SWR** for data fetching with 5-second polling intervals

## Design System

- **Font:** Inter via Google Fonts
- **Base font size:** 16px (`text-base` = 1rem)
- **Border radius:** 0.5rem (`rounded-lg`) on all cards, badges, buttons
- **Severity palette:**
  - Critical: `red-600` background, `red-50` text badge bg
  - Warning: `amber-500` background, `amber-50` text badge bg
  - Info/Pass: `green-500` background, `green-50` text badge bg
  - Fail: `red-600` (same as Critical)
  - Warn (scan): `amber-500` (same as Warning)
- **Layout:** slate-900 sidebar, slate-50 main content area, white cards
- **Spacing:** consistent use of Tailwind spacing scale

## ClawTower API

The dashboard connects to a ClawTower instance at the URL in the `CLAWTOWER_API_URL` environment variable (default: `http://localhost:9000/twins/clawtower`). Auth is not required (ClawTower auth is disabled).

All ClawTower endpoints are proxied through Next.js API routes at `/api/ct/*` to avoid CORS issues. The proxy forwards request method, headers, query params, and body.

### Endpoints (via proxy)

| Dashboard Route | ClawTower Endpoint | Method |
|----------------|-------------------|--------|
| `/api/ct/health` | `/api/health` | GET |
| `/api/ct/status` | `/api/status` | GET |
| `/api/ct/alerts` | `/api/alerts` | GET |
| `/api/ct/security` | `/api/security` | GET |
| `/api/ct/scans` | `/api/scans` | GET |
| `/api/ct/pending` | `/api/pending` | GET |
| `/api/ct/pending/[id]/approve` | `/api/pending/{id}/approve` | POST |
| `/api/ct/pending/[id]/deny` | `/api/pending/{id}/deny` | POST |
| `/api/ct/evidence` | `/api/evidence` | GET |
| `/api/ct/approvals` | `/api/approvals` | POST |
| `/api/ct/approvals/[id]` | `/api/approvals/{id}` | GET |
| `/api/ct/approvals/[id]/resolve` | `/api/approvals/{id}/resolve` | POST |
| `/api/ct/hooks/slack` | `/api/hooks/slack` | POST |
| `/api/ct/hooks/discord` | `/api/hooks/discord` | POST |

## Pages

### Dashboard Home (`/`)

The main page shows three sections:

1. **Health Status Bar** — top strip showing:
   - Connection status (healthy/unhealthy based on `/api/ct/health`)
   - ClawTower version
   - Uptime (formatted as days/hours/minutes)
   - Time since last alert (from `last_alert_age_seconds`, or "No alerts" if null)
   - Active modules (auditd, network, behavior, firewall — green dot if enabled)

2. **Alert Feed** — scrollable list of the latest 100 alerts from `/api/ct/alerts`:
   - Each alert card shows: timestamp (relative, e.g., "2m ago"), severity badge (CRIT/WARN/INFO with color), source module badge, message text
   - Sorted newest-first
   - Severity filter buttons at the top (All / Critical / Warning / Info)

3. **Security Posture Panel** — right sidebar with data from `/api/ct/security`:
   - Severity breakdown: three counters (Critical, Warning, Info) with colored backgrounds
   - Alerts by source: horizontal bar chart or list showing count per source module
   - Total alerts counter
   - Parity status: mismatch counter with warning indicator if > 0

### Scanner Results (`/scans`)

A sortable, filterable table of results from `/api/ct/scans`:

- Columns: Category, Status (badge), Details, Timestamp
- Status badges: Pass (green), Warn (amber), Fail (red)
- Sortable by Category (alpha) and Status (Fail first, then Warn, then Pass)
- Filter buttons: All / Fail / Warn / Pass
- Summary row at top: "X Pass, Y Warn, Z Fail out of N scans"

### Pending Actions (`/pending`)

Containment actions awaiting human approval from `/api/ct/pending`:

- Each pending action card shows:
  - Threat source and severity badge
  - Threat message
  - Mode badge: "Gate" (blue) or "Reactive" (purple)
  - Proposed actions list (e.g., "kill_process(pid=4821)", "lock_clawsudo")
  - Playbook name (if set)
  - Age timer (e.g., "45s ago")
  - **Approve** (green) and **Deny** (red) buttons

- Clicking Approve sends `POST /api/ct/pending/{id}/approve` with body `{ "by": "dashboard_user" }`
- Clicking Deny sends `POST /api/ct/pending/{id}/deny` with body `{ "by": "dashboard_user" }`
- After action, the card updates to show the resolution (approved/denied) and buttons are disabled
- Optional: bulk approve/deny checkboxes

### Approvals (`/approvals`)

Two sections:

1. **Submit Approval Request** — form with fields:
   - Command (required text input)
   - Agent name (text input, default "unknown")
   - Context (textarea)
   - Severity (dropdown: info / warning / critical, default "warning")
   - Timeout seconds (number input, default 300)
   - Submit button → `POST /api/ct/approvals`
   - On submit, shows the returned request ID and starts polling

2. **Approval Status** — shows active approval requests:
   - ID, status badge (pending/approved/denied/timed_out), command text
   - For pending items: Approve and Deny buttons
   - Approve sends `POST /api/ct/approvals/{id}/resolve` with `{ "approved": true, "by": "dashboard_user", "via": "dashboard" }`
   - Deny sends same with `"approved": false`
   - Poll `/api/ct/approvals/{id}` every 2 seconds while status is "pending"

### Evidence (`/evidence`)

Compliance evidence viewer from `/api/ct/evidence`:

1. **Controls bar:**
   - Framework selector dropdown: SOC 2, NIST 800-53, CIS Controls v8, MITRE ATT&CK
   - Period input (days, default 30)
   - "Generate" button to fetch evidence bundle

2. **Compliance Report section:**
   - Framework name and reporting period
   - Alert summary: total, critical, warning, info counts
   - Scanner summary: total scans, pass/warn/fail counts
   - **Control Findings table:** control_id, control_name, status badge (Pass/Finding/Critical), alert_count, highest_severity, categories list

3. **Audit Chain Integrity:**
   - Badge: "Verified" (green) or "Tampered" (red) based on `integrity_verified`
   - Chain file path and total entries count
   - Verification error message if present

4. **Policy Versions:**
   - List of loaded policy files
   - List of IOC/Barnacle databases
   - Active agent profile (if set)

## Shared Layout

- **Sidebar navigation** (left, slate-900 background):
  - ClawTower logo/text at top
  - Nav links: Dashboard, Scans, Pending, Approvals, Evidence
  - Active page highlighted
- **Main content area** (right, slate-50 background)
- **Responsive:** sidebar collapses to hamburger menu on mobile

## Data Fetching

All data is fetched via SWR hooks with automatic revalidation:

```typescript
// Example hook pattern
function useAlerts() {
  return useSWR('/api/ct/alerts', fetcher, { refreshInterval: 5000 })
}
```

Each page's data refreshes every 5 seconds. Error states show a red banner with the error message. Loading states show skeleton placeholders.

## Environment Variables

```
CLAWTOWER_API_URL=http://localhost:9000/twins/clawtower
```

## Project Structure

```
clawtower/
  package.json
  .env.local
  src/
    app/
      page.tsx                         # Dashboard home
      layout.tsx                       # Shared layout with sidebar
      globals.css
      scans/page.tsx                   # Scanner results
      pending/page.tsx                 # Pending actions
      approvals/page.tsx               # Approval workflow
      evidence/page.tsx                # Compliance evidence
      api/
        ct/
          health/route.ts              # Proxy → /api/health
          status/route.ts              # Proxy → /api/status
          alerts/route.ts              # Proxy → /api/alerts
          security/route.ts            # Proxy → /api/security
          scans/route.ts               # Proxy → /api/scans
          pending/
            route.ts                   # Proxy → /api/pending
            [id]/
              approve/route.ts         # Proxy → /api/pending/{id}/approve
              deny/route.ts            # Proxy → /api/pending/{id}/deny
          evidence/route.ts            # Proxy → /api/evidence
          approvals/
            route.ts                   # Proxy → /api/approvals (POST)
            [id]/
              route.ts                 # Proxy → /api/approvals/{id} (GET)
              resolve/route.ts         # Proxy → /api/approvals/{id}/resolve
          hooks/
            slack/route.ts             # Proxy → /api/hooks/slack
            discord/route.ts           # Proxy → /api/hooks/discord
    components/
      Sidebar.tsx                      # Navigation sidebar
      HealthBar.tsx                    # Health status strip
      AlertCard.tsx                    # Single alert display
      AlertFeed.tsx                    # Scrollable alert list with filters
      SecurityPosture.tsx              # Severity breakdown + alerts by source
      ScanTable.tsx                    # Scanner results table
      PendingActionCard.tsx            # Pending action with approve/deny
      ApprovalForm.tsx                 # Submit approval request form
      ApprovalStatus.tsx               # Approval polling display
      EvidenceViewer.tsx               # Compliance report viewer
      SeverityBadge.tsx                # Reusable severity badge component
      StatusBadge.tsx                  # Reusable Pass/Warn/Fail badge
    hooks/
      useHealth.ts                     # SWR hook for /api/ct/health
      useStatus.ts                     # SWR hook for /api/ct/status
      useAlerts.ts                     # SWR hook for /api/ct/alerts
      useSecurity.ts                   # SWR hook for /api/ct/security
      useScans.ts                      # SWR hook for /api/ct/scans
      usePending.ts                    # SWR hook for /api/ct/pending
    lib/
      fetcher.ts                       # SWR fetcher function
      formatTime.ts                    # Time formatting helpers
  tailwind.config.ts
  next.config.ts
  tsconfig.json
```

## Acceptance Criteria

- `npm run dev` starts the app on port 3000
- Dashboard home shows live alert feed, health status, and security posture
- All data refreshes every 5 seconds via SWR polling
- Scanner results table is sortable and filterable by status
- Pending actions can be approved or denied via buttons
- Approval workflow: submit form works, status polls until resolved
- Evidence viewer shows compliance reports for all four frameworks
- Severity badges use correct color palette throughout
- Inter font, 0.5rem border radius, slate sidebar throughout
- All proxy routes correctly forward to CLAWTOWER_API_URL
- Error states show meaningful messages (not blank pages)
- Empty states handled gracefully (no alerts = "No alerts yet" message)
