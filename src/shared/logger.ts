// src/shared/logger.ts
type LogLevel = 'debug' | 'info' | 'warn' | 'error'

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
}

// Read log level from process.env, defaulting to 'info'
const configLogLevel = (process.env.LOG_LEVEL?.toLowerCase() as LogLevel) ?? 'info'
const currentLevelNum = LOG_LEVELS[configLogLevel] ?? 1

function log(level: LogLevel, message: string, extra: Record<string, any> = {}) {
  const levelNum = LOG_LEVELS[level] ?? 1
  if (levelNum < currentLevelNum) return

  const logLine = {
    level,
    ts: new Date().toISOString(),
    message,
    trace_id: extra.traceId ?? '', // placeholder for future OTEL tracing
    span_id: extra.spanId ?? '',   // placeholder for future OTEL tracing
    ...extra,
  }
  
  if (level === 'error') {
    console.error(JSON.stringify(logLine))
  } else {
    console.log(JSON.stringify(logLine))
  }
}

export const logger = {
  debug: (msg: string, extra?: Record<string, any>) => log('debug', msg, extra),
  info: (msg: string, extra?: Record<string, any>) => log('info', msg, extra),
  warn: (msg: string, extra?: Record<string, any>) => log('warn', msg, extra),
  error: (msg: string, extra?: Record<string, any>) => log('error', msg, extra),
}
