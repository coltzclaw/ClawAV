# Response Engine Design

## Concept

A policy-driven automated response system that intercepts or reacts to security threats, holds them for human approval via Slack/TUI/API, and executes containment actions on approval or denies on timeout.

## Two Response Modes

**Gate mode** — for actions flowing through ClawTower control points (clawsudo, API proxy, netpolicy). The action is intercepted and held mid-flight. The agent's request blocks until approved, denied, or timed out (2 min default → deny with reason).

**Reactive mode** — for threats detected after the fact (auditd, sentinel, scanner). ClawTower proposes a containment action. The threat may be in progress. Same 2-minute approval window, but the damage clock is already ticking.

## Six Containment Actions

| Action | Mechanism | Reversible? |
|---|---|---|
| `kill_process` | SIGKILL PID/process group | No |
| `suspend_process` | SIGSTOP (freeze, preserve state) | Yes (SIGCONT) |
| `drop_network` | iptables rule blocking outbound for agent UID | Yes (remove rule) |
| `revoke_api_keys` | Proxy returns 403, stops forwarding | Yes (re-enable) |
| `freeze_filesystem` | chattr +i on watched paths | Yes (chattr -i) |
| `lock_clawsudo` | Deny all sudo for agent until manual unlock | Yes (unlock) |

## Response Playbooks

YAML-defined bundles of actions tied to threat categories:

```yaml
playbooks:
  exfiltration:
    description: "Data exfiltration containment"
    actions: [suspend_process, drop_network, revoke_api_keys]
    trigger_on: ["dns_exfil", "data_staging", "unauthorized_upload"]

  persistence:
    description: "Persistence mechanism containment"
    actions: [suspend_process, lock_clawsudo, freeze_filesystem]
    trigger_on: ["cron_persistence", "service_install", "startup_modification"]

  compromise:
    description: "Full agent compromise response"
    actions: [suspend_process, drop_network, revoke_api_keys, freeze_filesystem, lock_clawsudo]
    trigger_on: ["prompt_injection", "container_escape", "privilege_escalation"]
```

Individual ad-hoc actions also available from TUI/API for scenarios not covered by playbooks.

## Approval Flow

1. Threat detected → response engine matches to playbook or proposes individual action
2. **Pending action created** with unique ID, threat context, proposed actions, timestamp
3. Notification sent to all three surfaces simultaneously:
   - **Slack:** Interactive message with threat summary, proposed actions, reply instructions
   - **TUI:** Modal popup with threat details, Approve/Deny selection, optional message box for audit annotation
   - **API:** `GET /api/pending` lists pending actions, `POST /api/pending/{id}/approve` or `/deny` with optional message
4. **First response wins** — approved or denied from any surface resolves it everywhere
5. **2-minute timeout** → auto-deny, logged as "expired — no human response"
6. **Deny response** returned to agent with reason: "Action blocked by ClawTower security policy: [threat category]. Contact administrator."

## Approval Response Record

All approvals/denials include:
- Action ID
- Decision (approve/deny/expired)
- Human annotation (optional message from the popup)
- Surface it came from (slack/tui/api)
- Timestamp
- Logged to the hash-chained audit trail

## Severity Routing

| Severity | Default Behavior | Configurable? |
|---|---|---|
| Critical | Always gate + approve | No — hardcoded |
| Warning | Gate + approve | Yes — can be set to alert-only or auto-deny |
| Info | Alert only | Yes — can be escalated |

## Core Types

```rust
pub struct PendingAction {
    pub id: String,              // unique ID (UUID)
    pub threat_source: String,   // which module detected it
    pub threat_message: String,  // what happened
    pub severity: Severity,
    pub mode: ResponseMode,      // Gate or Reactive
    pub actions: Vec<ContainmentAction>,
    pub playbook: Option<String>, // which playbook matched, if any
    pub created_at: Instant,
    pub timeout: Duration,       // default 2 min
    pub status: PendingStatus,
}

pub enum ResponseMode {
    Gate,     // action is held, agent is blocked
    Reactive, // threat detected post-fact, containment proposed
}

pub enum ContainmentAction {
    KillProcess { pid: u32 },
    SuspendProcess { pid: u32 },
    DropNetwork { uid: u32 },
    RevokeApiKeys,
    FreezeFilesystem { paths: Vec<String> },
    LockClawsudo,
}

pub enum PendingStatus {
    AwaitingApproval,
    Approved { by: String, message: Option<String>, surface: String },
    Denied { by: String, message: Option<String>, surface: String },
    Expired,
}
```

## Integration Points

- **Alert pipeline:** Response engine subscribes to `alert_tx` after the aggregator, evaluates each alert against playbook triggers
- **clawsudo:** Already blocks — add a channel back to response engine to hold/release
- **API proxy:** Add hold/release mechanism on forwarding
- **netpolicy:** Add dynamic iptables rule insertion/removal
- **TUI:** New "Pending" indicator in tab bar when actions await approval, popup on active tab
- **Slack:** Notification with reply instructions (APPROVE-{id} / DENY-{id})
- **API server:** Two new endpoints: `GET /api/pending`, `POST /api/pending/{id}/{action}`

## Slack Consideration

Current Slack integration is webhook-only (one-way). Interactive buttons require either a Slack app with Events API or Socket Mode. For v1, Slack sends notification with reply instruction format ("reply APPROVE-{id} or DENY-{id}") monitored via incoming channel. Upgrade to proper Slack app interactivity is a follow-up.
