// src/shared/db.ts
import postgres from 'postgres'
import { readdir, readFile } from 'fs/promises'
import { join } from 'path'
import { fileURLToPath } from 'url'
import { dirname } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

export const sql = postgres(process.env.DATABASE_URL!, {
  max: 10,
  transform: postgres.camel,
})

export async function runMigrations(): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS _migrations (
      name    TEXT PRIMARY KEY,
      run_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `
  const applied = new Set(
    (await sql`SELECT name FROM _migrations`).map((r: { name: string }) => r.name)
  )
  const dir = join(__dirname, '../migrations')
  const files = (await readdir(dir)).filter((f: string) => f.endsWith('.sql')).sort()
  for (const file of files) {
    if (applied.has(file)) continue
    const content = await readFile(join(dir, file), 'utf-8')
    await sql.begin(async (tx: typeof sql) => {
      await tx.unsafe(content)
      await tx`INSERT INTO _migrations (name) VALUES (${file})`
    })
    console.log(`[db] migrated: ${file}`)
  }
}

export async function writeAuditLog(
  actorDid: string,
  action: string,
  result: 'success' | 'failure',
  targetId?: string
): Promise<void> {
  await sql`
    INSERT INTO audit_log (actor_did, action, target_id, result)
    VALUES (${actorDid}, ${action}, ${targetId ?? null}, ${result})
  `
}
