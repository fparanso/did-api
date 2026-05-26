// src/domains/oauth/repository.ts
import { sql } from '../../shared/db.js'
import { randomUUID } from 'crypto'

// PAR requests ----------------------------------------------------------------

export async function insertParRequest(params: {
  clientId: string
  codeChallenge: string
  codeChallengeMethod: string
  redirectUri: string
  scope: string
}): Promise<string> {
  const requestUri = `urn:ietf:params:oauth:request_uri:${randomUUID()}`
  const expiresAt = new Date(Date.now() + 90_000) // 90 seconds
  await sql`
    INSERT INTO oauth_par_requests
      (request_uri, client_id, code_challenge, code_challenge_method, redirect_uri, scope, expires_at)
    VALUES
      (${requestUri}, ${params.clientId}, ${params.codeChallenge},
       ${params.codeChallengeMethod}, ${params.redirectUri}, ${params.scope}, ${expiresAt})
  `
  return requestUri
}

export async function consumeParRequest(requestUri: string): Promise<{
  clientId: string; codeChallenge: string; redirectUri: string; scope: string
} | null> {
  const [row] = await sql`
    DELETE FROM oauth_par_requests
    WHERE request_uri = ${requestUri} AND expires_at > now()
    RETURNING client_id, code_challenge, redirect_uri, scope
  `
  if (!row) return null
  return {
    clientId: row.clientId as string,
    codeChallenge: row.codeChallenge as string,
    redirectUri: row.redirectUri as string,
    scope: row.scope as string,
  }
}

// Auth codes ------------------------------------------------------------------

export async function insertAuthCode(params: {
  clientId: string
  redirectUri: string
  codeChallenge: string
  scope: string
  did: string
}): Promise<string> {
  const code = randomUUID().replace(/-/g, '')
  const expiresAt = new Date(Date.now() + 600_000) // 10 minutes
  await sql`
    INSERT INTO oauth_auth_codes
      (code, client_id, redirect_uri, code_challenge, scope, did, expires_at)
    VALUES
      (${code}, ${params.clientId}, ${params.redirectUri},
       ${params.codeChallenge}, ${params.scope}, ${params.did}, ${expiresAt})
  `
  return code
}

export async function consumeAuthCode(code: string): Promise<{
  clientId: string; redirectUri: string; codeChallenge: string; scope: string; did: string
} | null> {
  const [row] = await sql`
    UPDATE oauth_auth_codes SET used = true
    WHERE code = ${code} AND used = false AND expires_at > now()
    RETURNING client_id, redirect_uri, code_challenge, scope, did
  `
  if (!row) return null
  return {
    clientId: row.clientId as string,
    redirectUri: row.redirectUri as string,
    codeChallenge: row.codeChallenge as string,
    scope: row.scope as string,
    did: row.did as string,
  }
}

// DPoP nonces -----------------------------------------------------------------

export async function createDpopNonce(): Promise<string> {
  const nonce = randomUUID().replace(/-/g, '')
  const expiresAt = new Date(Date.now() + 300_000) // 5 minutes
  await sql`
    INSERT INTO oauth_dpop_nonces (nonce, expires_at)
    VALUES (${nonce}, ${expiresAt})
  `
  return nonce
}

export async function isDpopNonceValid(nonce: string): Promise<boolean> {
  const [row] = await sql`
    SELECT 1 FROM oauth_dpop_nonces WHERE nonce = ${nonce} AND expires_at > now()
  `
  return !!row
}
