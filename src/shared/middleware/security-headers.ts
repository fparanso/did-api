import type { Context, Next } from 'hono'

export async function securityHeadersMiddleware(c: Context, next: Next) {
  await next()
  c.res.headers.set('X-Content-Type-Options', 'nosniff')
  c.res.headers.set('X-Frame-Options', 'DENY')
  c.res.headers.set('X-XSS-Protection', '1; mode=block')
  c.res.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  c.res.headers.set('Content-Security-Policy', "default-src 'none'")
  c.res.headers.set('Cache-Control', 'no-store')
  c.res.headers.set('Referrer-Policy', 'no-referrer')
}
