// src/shared/metrics.ts
interface RouteStats {
  requests: number
  errors: number
  latencies: number[]
}

const stats: Record<string, RouteStats> = {}
const startTime = Date.now()

export function recordMetric(method: string, routePath: string, status: number, ms: number) {
  const key = `${method} ${routePath}`
  if (!stats[key]) {
    stats[key] = { requests: 0, errors: 0, latencies: [] }
  }

  const s = stats[key]
  s.requests++
  if (status >= 400) {
    s.errors++
  }

  s.latencies.push(ms)
  if (s.latencies.length > 1000) {
    s.latencies.shift() // Sliding window of the last 1000 request latencies
  }
}

export function getMetrics() {
  const result: Record<string, { requests: number; errors: number; p99_ms: number }> = {}

  for (const [key, s] of Object.entries(stats)) {
    let p99 = 0
    if (s.latencies.length > 0) {
      const sorted = [...s.latencies].sort((a, b) => a - b)
      const idx = Math.min(
        sorted.length - 1,
        Math.max(0, Math.ceil(sorted.length * 0.99) - 1)
      )
      p99 = sorted[idx]
    }
    result[key] = {
      requests: s.requests,
      errors: s.errors,
      p99_ms: p99,
    }
  }

  return {
    uptime_ms: Date.now() - startTime,
    routes: result,
  }
}
