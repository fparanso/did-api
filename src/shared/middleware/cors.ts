import { cors } from 'hono/cors'

const origin = process.env.CORS_ORIGIN ?? 'http://localhost:3000'

export const corsMiddleware = cors({
  origin,
  allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  exposeHeaders: ['Content-Type'],
  maxAge: 600,
  credentials: false,
})
