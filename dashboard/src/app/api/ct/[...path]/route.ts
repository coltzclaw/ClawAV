import { NextRequest } from 'next/server'

// DTU twin stores nested objects as JSON strings in SQLite — recursively parse them
function deepParseJsonStrings(value: unknown): unknown {
  if (value === null || value === undefined) return value
  if (Array.isArray(value)) return value.map(deepParseJsonStrings)
  if (typeof value === 'object') {
    const result: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      result[k] = deepParseJsonStrings(v)
    }
    return result
  }
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (trimmed.length > 1 &&
        ((trimmed[0] === '{' && trimmed[trimmed.length - 1] === '}') ||
         (trimmed[0] === '[' && trimmed[trimmed.length - 1] === ']'))) {
      try {
        return deepParseJsonStrings(JSON.parse(trimmed))
      } catch {
        return value
      }
    }
  }
  return value
}

// Endpoints that return arrays (list resources) vs single objects
const LIST_ENDPOINTS = ['alerts', 'scans', 'pending']

// Build forwarded headers (strip hop-by-hop)
function forwardHeaders(reqHeaders: Headers): Record<string, string> {
  const headers: Record<string, string> = {}
  reqHeaders.forEach((value, key) => {
    const lower = key.toLowerCase()
    if (lower === 'host' || lower === 'connection' || lower === 'transfer-encoding' || lower === 'content-length') return
    headers[key] = value
  })
  return headers
}

// Unwrap DTU envelope and deep-parse JSON strings
function unwrapDtuResponse(rawBody: string, apiPath: string): unknown {
  try {
    let parsed = JSON.parse(rawBody)
    parsed = deepParseJsonStrings(parsed)

    // Unwrap DTU envelope {data: [...], has_more: boolean}
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) &&
        'data' in parsed && Array.isArray((parsed as Record<string, unknown>).data)) {
      const dataArr = (parsed as Record<string, unknown>).data as unknown[]
      const basePath = apiPath.split('/')[0]
      if (LIST_ENDPOINTS.includes(basePath)) {
        return dataArr
      } else if (dataArr.length === 1) {
        return dataArr[0]
      } else if (dataArr.length === 0) {
        return null
      } else {
        return dataArr
      }
    }
    return parsed
  } catch {
    return null
  }
}

// Fetch a single resource from DTU by path
async function dtuGet(baseUrl: string, path: string, headers: Record<string, string>): Promise<{ data: unknown; status: number }> {
  try {
    const resp = await fetch(`${baseUrl}/api/${path}`, { method: 'GET', headers })
    const body = await resp.text()
    if (!resp.ok) return { data: null, status: resp.status }
    return { data: unwrapDtuResponse(body, path), status: resp.status }
  } catch {
    return { data: null, status: 502 }
  }
}

// PUT a resource to DTU
async function dtuPut(baseUrl: string, path: string, headers: Record<string, string>, body: Record<string, unknown>): Promise<number> {
  try {
    const resp = await fetch(`${baseUrl}/api/${path}`, {
      method: 'PUT',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    return resp.status
  } catch {
    return 502
  }
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

async function proxyRequest(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const baseUrl = process.env.CLAWTOWER_API_URL || 'http://localhost:9000/twins/clawtower'
  const { path } = await params
  const apiPath = path.join('/')
  const headers = forwardHeaders(request.headers)

  // ── Webhook endpoints: handle directly (DTU doesn't have hook tables) ──
  if (apiPath === 'hooks/slack') {
    return jsonResponse({ ok: true }, 200)
  }
  if (apiPath === 'hooks/discord') {
    return jsonResponse({ error: 'not implemented' }, 501)
  }

  // ── Approval creation: inject status=pending ──
  if (apiPath === 'approvals' && request.method === 'POST') {
    const bodyText = await request.text()
    let body: Record<string, unknown> = {}
    try { body = JSON.parse(bodyText) } catch { /* ignore */ }
    body.status = 'pending'
    const resp = await fetch(`${baseUrl}/api/approvals`, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    const raw = await resp.text()
    const parsed = unwrapDtuResponse(raw, apiPath)
    return jsonResponse(parsed, resp.status)
  }

  // ── Approval resolve: check status, guard double-resolve ──
  const resolveMatch = apiPath.match(/^approvals\/([^/]+)\/resolve$/)
  if (resolveMatch && request.method === 'POST') {
    const id = resolveMatch[1]
    const { data: approval, status } = await dtuGet(baseUrl, `approvals/${id}`, headers)
    if (status === 404 || !approval) return jsonResponse({ error: 'not found' }, 404)

    const currentStatus = (approval as Record<string, unknown>).status
    if (currentStatus && currentStatus !== 'pending') {
      return jsonResponse({ error: 'already resolved' }, 405)
    }

    const bodyText = await request.text()
    let body: Record<string, unknown> = {}
    try { body = JSON.parse(bodyText) } catch { /* ignore */ }
    const newStatus = body.approved ? 'approved' : 'denied'

    await dtuPut(baseUrl, `approvals/${id}`, headers, {
      ...(approval as Record<string, unknown>),
      status: newStatus,
    })
    return jsonResponse({ ok: true }, 200)
  }

  // ── Approval GET: check for timeout ──
  const approvalGetMatch = apiPath.match(/^approvals\/([^/]+)$/)
  if (approvalGetMatch && request.method === 'GET') {
    const id = approvalGetMatch[1]
    const { data: approval, status } = await dtuGet(baseUrl, `approvals/${id}`, headers)
    if (status === 404 || !approval) return jsonResponse({ error: 'not found' }, 404)

    const record = approval as Record<string, unknown>
    // Check timeout: if status is pending and created + timeout_secs < now
    if (record.status === 'pending' && record.created && record.timeout_secs) {
      const created = Number(record.created)
      const timeout = Number(record.timeout_secs)
      const now = Math.floor(Date.now() / 1000)
      if (now - created >= timeout) {
        record.status = 'timed_out'
        // Update in DTU too
        await dtuPut(baseUrl, `approvals/${id}`, headers, record)
      }
    }
    return jsonResponse(record, 200)
  }

  // ── Pending actions: approve/deny with existence check via list ──
  const pendingActionMatch = apiPath.match(/^pending\/([^/]+)\/(approve|deny)$/)
  if (pendingActionMatch && request.method === 'POST') {
    const id = pendingActionMatch[1]
    const action = pendingActionMatch[2]

    // Check if the pending action exists by fetching the list and finding by ID
    const { data: pendingList } = await dtuGet(baseUrl, 'pending', headers)
    const items = Array.isArray(pendingList) ? pendingList : []
    const pending = items.find((item: unknown) => (item as Record<string, unknown>).id === id)
    if (!pending) return jsonResponse({ error: 'not found' }, 404)

    const newStatus = action === 'approve' ? 'approved' : 'denied'
    const bodyText = await request.text()
    let body: Record<string, unknown> = {}
    try { body = JSON.parse(bodyText) } catch { /* ignore */ }

    await dtuPut(baseUrl, `pending/${id}`, headers, {
      ...(pending as Record<string, unknown>),
      status: newStatus,
      resolved_by: body.by || 'dashboard',
    })
    return jsonResponse({ id, result: newStatus }, 200)
  }

  // ── Evidence: apply framework/period from query params ──
  if (apiPath === 'evidence' && request.method === 'GET') {
    const framework = request.nextUrl.searchParams.get('framework')
    const period = request.nextUrl.searchParams.get('period')

    const url = new URL(`${baseUrl}/api/evidence`)
    request.nextUrl.searchParams.forEach((value, key) => url.searchParams.set(key, value))

    const resp = await fetch(url.toString(), { method: 'GET', headers })
    const raw = await resp.text()
    let data = unwrapDtuResponse(raw, apiPath)

    // Apply framework/period overrides to the response
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const record = data as Record<string, unknown>
      if (record.compliance_report && typeof record.compliance_report === 'object') {
        const report = record.compliance_report as Record<string, unknown>
        if (framework) report.framework = framework
        if (period) report.period_days = Number(period)
      }
    }
    return jsonResponse(data, resp.status)
  }

  // ── Default proxy: forward to DTU ──
  const url = new URL(`${baseUrl}/api/${apiPath}`)
  request.nextUrl.searchParams.forEach((value, key) => url.searchParams.set(key, value))

  const fetchOptions: RequestInit = {
    method: request.method,
    headers,
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    const body = await request.text()
    if (body) fetchOptions.body = body
  }

  try {
    const upstream = await fetch(url.toString(), fetchOptions)
    const rawBody = await upstream.text()

    const responseHeaders: Record<string, string> = {}
    const ct = upstream.headers.get('content-type')
    responseHeaders['Content-Type'] = ct?.includes('application/json') ? 'application/json' : (ct || 'application/json')

    let body = rawBody
    if (responseHeaders['Content-Type'].includes('application/json') && rawBody.trim()) {
      const parsed = unwrapDtuResponse(rawBody, apiPath)
      if (parsed !== null) body = JSON.stringify(parsed)
    }

    return new Response(body, { status: upstream.status, headers: responseHeaders })
  } catch (error) {
    const message = error instanceof Error && error.name === 'AbortError'
      ? 'Request timed out'
      : 'Upstream connection failed'
    return jsonResponse({ error: message, detail: String(error) }, 502)
  }
}

export const GET = proxyRequest
export const POST = proxyRequest
export const PUT = proxyRequest
export const DELETE = proxyRequest
export const PATCH = proxyRequest
