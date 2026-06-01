// src/shared/config.ts
import { z } from 'zod'

const envSchema = z.object({
  DATABASE_URL: z.string().url('DATABASE_URL must be a valid URL'),
  KEY_ENCRYPTION_SECRET: z.string().regex(/^[0-9a-fA-F]{64}$/, 'KEY_ENCRYPTION_SECRET must be a 64-character hex string (32 bytes)'),
  JWT_SECRET: z.string().min(1, 'JWT_SECRET is required'),
  ADMIN_SECRET: z.string().min(1, 'ADMIN_SECRET is required'),
  CORS_ORIGIN: z.string().url('CORS_ORIGIN must be a valid URL').default('http://localhost:3000'),
  PORT: z.string().regex(/^\d+$/).transform(Number).default('3000'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  ISSUER_HOST: z.string().url('ISSUER_HOST must be a valid URL').default('http://localhost:3000'),
})

const parsed = envSchema.safeParse(process.env)
if (!parsed.success) {
  console.error('❌ Environment validation failed:')
  console.error(parsed.error.format())
  throw new Error(`EnvironmentValidationError: ${parsed.error.message}`)
}

export const env = parsed.data
