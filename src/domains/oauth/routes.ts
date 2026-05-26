// src/domains/oauth/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import {
  buildIssuerMetadata, handlePar, handleAuthorize, handleToken,
  handleNonce, handleCredentialEndpoint,
} from './service.js'
import { jwtMiddleware } from '../auth/middleware.js'
import type { HonoVariables } from '../../shared/types.js'
import { AppError } from '../../shared/errors.js'

export const oauthRouter = new Hono<{ Variables: HonoVariables }>()
export const wellKnownRouter = new Hono()

wellKnownRouter.get('/openid-credential-issuer', c => c.json(buildIssuerMetadata()))

oauthRouter.post('/par', async c => {
  const body = await c.req.parseBody()
  const parsed = z.object({
    client_id: z.string(),
    code_challenge: z.string(),
    code_challenge_method: z.string(),
    redirect_uri: z.string().url(),
    scope: z.string(),
  }).safeParse(body)
  if (!parsed.success) return c.json({ error: 'invalid_request' }, 400)
  const { requestUri, expiresIn } = await handlePar({
    clientId: parsed.data.client_id,
    codeChallenge: parsed.data.code_challenge,
    codeChallengeMethod: parsed.data.code_challenge_method,
    redirectUri: parsed.data.redirect_uri,
    scope: parsed.data.scope,
  })
  return c.json({ request_uri: requestUri, expires_in: expiresIn }, 201)
})

oauthRouter.get('/authorize', jwtMiddleware, async c => {
  const requestUri = c.req.query('request_uri')
  if (!requestUri) return c.json({ error: 'invalid_request', error_description: 'Missing request_uri' }, 400)
  const redirectUrl = await handleAuthorize({ requestUri, did: c.get('did') })
  return c.redirect(redirectUrl, 302)
})

oauthRouter.post('/token', async c => {
  const body = await c.req.parseBody()
  const dpop = c.req.header('DPoP') ?? ''
  const requestUrl = `${getHost()}/oauth/token`
  const parsed = z.object({
    grant_type: z.literal('authorization_code'),
    code: z.string(),
    code_verifier: z.string(),
    client_id: z.string(),
    redirect_uri: z.string(),
  }).safeParse(body)
  if (!parsed.success) return c.json({ error: 'invalid_request' }, 400)
  const result = await handleToken({
    code: parsed.data.code,
    codeVerifier: parsed.data.code_verifier,
    clientId: parsed.data.client_id,
    redirectUri: parsed.data.redirect_uri,
    dpopProof: dpop,
    requestUrl,
  })
  return c.json({
    access_token: result.accessToken,
    token_type: result.tokenType,
    expires_in: result.expiresIn,
    c_nonce: result.cNonce,
  })
})

oauthRouter.post('/nonce', async c => {
  const { cNonce } = await handleNonce()
  return c.json({ c_nonce: cNonce })
})

oauthRouter.post('/credentials', async c => {
  const auth = c.req.header('Authorization') ?? ''
  if (!auth.startsWith('Bearer ') && !auth.startsWith('DPoP ')) {
    return c.json({ error: 'unauthorized' }, 401)
  }
  const accessToken = auth.replace(/^(Bearer|DPoP) /, '')
  const dpop = c.req.header('DPoP') ?? ''
  const requestUrl = `${getHost()}/oauth/credentials`
  const body = await c.req.json().catch(() => ({}))
  const parsed = z.object({
    format: z.enum(['dc+sd-jwt', 'mso_mdoc']),
    vct: z.string().optional(),
    doctype: z.string().optional(),
    proof: z.object({ proof_type: z.string(), jwt: z.string() }),
    claims: z.record(z.unknown()).optional(),
    name_spaces: z.record(z.record(z.unknown())).optional(),
  }).safeParse(body)
  if (!parsed.success) return c.json({ error: 'invalid_request', description: parsed.error.message }, 400)
  const result = await handleCredentialEndpoint({
    accessToken, dpopProof: dpop, requestUrl,
    proof: parsed.data.proof,
    format: parsed.data.format,
    vct: parsed.data.vct,
    docType: parsed.data.doctype,
    nameSpaces: parsed.data.name_spaces,
    claims: parsed.data.claims,
  })
  return c.json(result)
})

function getHost(): string {
  return process.env.ISSUER_HOST ?? 'http://localhost:3000'
}
