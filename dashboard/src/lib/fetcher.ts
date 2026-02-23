// Recursively parse any string values that look like JSON objects/arrays.
// The DTU engine stores nested objects as JSON strings in SQLite.
export function deepParseJsonStrings(value: unknown): unknown {
  if (value === null || value === undefined) return value
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (trimmed.length > 1 && (trimmed[0] === '{' || trimmed[0] === '[')) {
      try {
        const parsed = JSON.parse(trimmed)
        return deepParseJsonStrings(parsed)
      } catch {
        return value
      }
    }
    return value
  }
  if (Array.isArray(value)) {
    return value.map(deepParseJsonStrings)
  }
  if (typeof value === 'object') {
    const result: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>)) {
      result[key] = deepParseJsonStrings((value as Record<string, unknown>)[key])
    }
    return result
  }
  return value
}

export const fetcher = (url: string) =>
  fetch(url).then((res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return res.json()
  })

// DTU engine wraps GET responses in {data: [...], has_more: boolean}
// singleFetcher extracts the first item for singleton endpoints
export const singleFetcher = (url: string) =>
  fetch(url).then((res) => {
    if (!res.ok) throw new Error('HTTP ' + res.status)
    return res.json()
  }).then((json) => {
    if (json && typeof json === 'object' && 'data' in json && Array.isArray(json.data)) {
      const item = json.data[0] || null
      return item ? deepParseJsonStrings(item) : null
    }
    return deepParseJsonStrings(json)
  })

// listFetcher extracts the array for list endpoints
export const listFetcher = (url: string) =>
  fetch(url).then((res) => {
    if (!res.ok) throw new Error('HTTP ' + res.status)
    return res.json()
  }).then((json) => {
    let arr: unknown[]
    if (json && typeof json === 'object' && 'data' in json && Array.isArray(json.data)) {
      arr = json.data
    } else {
      arr = Array.isArray(json) ? json : []
    }
    return arr.map((item) => deepParseJsonStrings(item))
  })
