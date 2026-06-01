// src/domains/oauth/service.ts
import { SignJWT, jwtVerify, importJWK, decodeJwt } from 'jose'
import type { JWK } from 'jose'
import { insertParRequest, consumeParRequest, insertAuthCode, consumeAuthCode,
  createDpopNonce, isDpopNonceValid,
  insertVpSession, findVpSession, findVpSessionByNonce, updateVpSession } from './repository.js'
import { getDidRecord } from '../did/service.js'
import { decryptKey } from '../../shared/crypto/keys.js'
import { issueSdJwt, verifySdJwtPresentation } from '../../shared/crypto/sd-jwt.js'
import { buildIssuerSigned } from '../../shared/crypto/mdoc.js'
import { AppError } from '../../shared/errors.js'
import { isIssuerTrusted } from '../trust/service.js'

function getHost(): string {
  return process.env.ISSUER_HOST ?? 'http://localhost:3000'
}

export function buildIssuerMetadata() {
  const host = getHost()
  return {
    credential_issuer: host,
    credential_endpoint: `${host}/oauth/credentials`,
    nonce_endpoint: `${host}/oauth/nonce`,
    authorization_servers: [host],
    token_endpoint: `${host}/oauth/token`,
    pushed_authorization_request_endpoint: `${host}/oauth/par`,
    credential_configurations_supported: {
      UniversityDegree: {
        format: 'dc+sd-jwt',
        vct: 'UniversityDegree',
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
      },
      mDL: {
        format: 'mso_mdoc',
        doctype: 'org.iso.18013.5.1.mDL',
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
      },
    },
  }
}

export async function handlePar(params: {
  clientId: string; codeChallenge: string; codeChallengeMethod: string
  redirectUri: string; scope: string
}): Promise<{ requestUri: string; expiresIn: number }> {
  if (params.codeChallengeMethod !== 'S256') {
    throw new AppError('INVALID_REQUEST', 'Only S256 code_challenge_method supported', 400)
  }
  const requestUri = await insertParRequest(params)
  return { requestUri, expiresIn: 90 }
}

export async function handleAuthorize(params: {
  requestUri: string; did: string
}): Promise<string> {
  const par = await consumeParRequest(params.requestUri)
  if (!par) throw new AppError('INVALID_REQUEST', 'request_uri not found or expired', 400)
  const code = await insertAuthCode({
    clientId: par.clientId,
    redirectUri: par.redirectUri,
    codeChallenge: par.codeChallenge,
    scope: par.scope,
    did: params.did,
  })
  return `${par.redirectUri}?code=${code}&iss=${encodeURIComponent(getHost())}`
}

async function verifyPkce(codeVerifier: string, codeChallenge: string): Promise<void> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))
  const computed = Buffer.from(hash).toString('base64url')
  if (computed !== codeChallenge) throw new AppError('INVALID_GRANT', 'PKCE verification failed', 400)
}

export async function verifyDpopProof(dpopHeader: string, method: string, url: string): Promise<JWK> {
  if (!dpopHeader) throw new AppError('INVALID_DPOP', 'Missing DPoP header', 401)
  const parts = dpopHeader.split('.')
  if (parts.length !== 3) throw new AppError('INVALID_DPOP', 'Malformed DPoP JWT', 401)
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString())
  if (header.typ !== 'dpop+jwt') throw new AppError('INVALID_DPOP', 'DPoP typ must be dpop+jwt', 401)
  const jwk: JWK = header.jwk
  const key = await importJWK(jwk, 'ES256')
  const { payload } = await jwtVerify(dpopHeader, key, { typ: 'dpop+jwt' })
  if (payload.htm !== method) throw new AppError('INVALID_DPOP', 'DPoP htm mismatch', 401)
  if (payload.htu !== url) throw new AppError('INVALID_DPOP', 'DPoP htu mismatch', 401)
  const iat = payload.iat as number
  if (Math.abs(Date.now() / 1000 - iat) > 60) throw new AppError('INVALID_DPOP', 'DPoP iat too old', 401)
  return jwk
}

export async function handleToken(params: {
  code: string; codeVerifier: string; clientId: string; redirectUri: string
  dpopProof: string; requestUrl: string
}): Promise<{ accessToken: string; tokenType: string; expiresIn: number; cNonce: string }> {
  const record = await consumeAuthCode(params.code)
  if (!record) throw new AppError('INVALID_GRANT', 'Authorization code invalid or expired', 400)
  if (record.clientId !== params.clientId) throw new AppError('INVALID_CLIENT', 'client_id mismatch', 401)
  if (record.redirectUri !== params.redirectUri) throw new AppError('INVALID_GRANT', 'redirect_uri mismatch', 400)

  await verifyPkce(params.codeVerifier, record.codeChallenge)
  await verifyDpopProof(params.dpopProof, 'POST', params.requestUrl)

  const secret = new TextEncoder().encode(process.env.JWT_SECRET!)
  const cNonce = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url')

  const accessToken = await new SignJWT({ did: record.did, scope: record.scope, cNonce })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('5m')
    .setIssuedAt()
    .sign(secret)

  return { accessToken, tokenType: 'DPoP', expiresIn: 300, cNonce }
}

export async function handleNonce(): Promise<{ cNonce: string }> {
  const cNonce = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url')
  return { cNonce }
}

export async function handleCredentialEndpoint(params: {
  accessToken: string; dpopProof: string; requestUrl: string
  proof: { proof_type: string; jwt: string }
  format: 'dc+sd-jwt' | 'mso_mdoc'
  vct?: string; docType?: string
  nameSpaces?: Record<string, Record<string, unknown>>
  claims?: Record<string, unknown>
}): Promise<{ credential: string }> {
  const secret = new TextEncoder().encode(process.env.JWT_SECRET!)
  const { payload } = await jwtVerify(params.accessToken, secret)
  const issuerDid = payload.did as string
  const cNonce = payload.cNonce as string

  await verifyDpopProof(params.dpopProof, 'POST', params.requestUrl)

  if (params.proof.proof_type !== 'jwt') {
    throw new AppError('INVALID_PROOF', 'Only jwt proof_type supported', 400)
  }
  const proofParts = params.proof.jwt.split('.')
  const proofHeader = JSON.parse(Buffer.from(proofParts[0], 'base64url').toString())
  if (proofHeader.typ !== 'openid4vci-proof+jwt') {
    throw new AppError('INVALID_PROOF', 'Proof JWT typ must be openid4vci-proof+jwt', 400)
  }
  const holderJwk: JWK = proofHeader.jwk
  const holderKey = await importJWK(holderJwk, 'ES256')
  const { payload: proofPayload } = await jwtVerify(params.proof.jwt, holderKey, { typ: 'openid4vci-proof+jwt' })
  if (proofPayload.nonce !== cNonce) throw new AppError('INVALID_PROOF', 'Proof nonce mismatch', 400)

  const issuerRecord = await getDidRecord(issuerDid)
  const issuerPrivateJwk: JWK = JSON.parse(await decryptKey(issuerRecord.privateKey))

  let credential: string
  if (params.format === 'dc+sd-jwt') {
    credential = await issueSdJwt({
      issuerPrivateJwk,
      issuerDid,
      subjectDid: issuerDid,
      vct: params.vct ?? 'VerifiableCredential',
      claims: params.claims ?? {},
      holderPublicJwk: holderJwk,
    })
  } else {
    credential = await buildIssuerSigned({
      issuerPrivateJwk,
      issuerDid,
      docType: params.docType ?? 'org.iso.18013.5.1.mDL',
      nameSpaces: params.nameSpaces ?? {},
      holderPublicJwk: holderJwk,
    })
  }

  return { credential }
}

export async function handleVpInitiate(params: {
  verifierDid: string | null
  dcqlQuery: unknown
}): Promise<{ sessionId: string; requestUri: string; nonce: string }> {
  const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url')
  const sessionId = await insertVpSession({ nonce, verifierDid: params.verifierDid, dcqlQuery: params.dcqlQuery })
  const requestUri = `${getHost()}/oauth/request/${sessionId}`
  return { sessionId, requestUri, nonce }
}

export async function buildSignedRequestObject(sessionId: string): Promise<string> {
  const session = await findVpSession(sessionId)
  if (!session) throw new AppError('NOT_FOUND', 'VP session not found', 404)

  const verifierDid = session.verifierDid
  if (!verifierDid) {
    throw new AppError('INVALID_STATE', 'Verifier DID not associated with session', 400)
  }

  const issuerRecord = await getDidRecord(verifierDid)
  const issuerPrivateJwk: JWK = JSON.parse(await decryptKey(issuerRecord.privateKey))

  const host = getHost()
  return new SignJWT({
    response_type: 'vp_token',
    response_mode: 'direct_post',
    response_uri: `${host}/oauth/direct_post`,
    client_id: verifierDid,
    nonce: session.nonce,
    dcql_query: session.dcqlQuery,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'oauth-authz-req+jwt' })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(await importJWK(issuerPrivateJwk, 'ES256'))
}

export async function handleDirectPost(params: {
  vpToken: string
  state?: string
}): Promise<void> {
  const token = params.vpToken.trim()
  const isSdJwt = token.includes('~')

  let nonce: string
  let disclosedClaims: unknown
  let issuerDid: string
  let valid: boolean

  if (isSdJwt) {
    const parts = token.split('~')
    const kbJwt = parts[parts.length - 1]
    const kbPayload = JSON.parse(Buffer.from(kbJwt.split('.')[1], 'base64url').toString())
    nonce = kbPayload.nonce
    const audience = kbPayload.aud as string

    const issuerJwt = parts[0]
    const payloadB64 = issuerJwt.split('.')[1]
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString())
    issuerDid = payload.iss as string

    const issuerRecord = await getDidRecord(issuerDid)
    const issuerPublicJwk: JWK = JSON.parse(issuerRecord.publicKey)

    const result = await verifySdJwtPresentation({
      combined: token, issuerPublicJwk, expectedNonce: nonce, expectedAudience: audience,
    })
    valid = result.valid
    disclosedClaims = result.disclosedClaims
  } else {
    nonce = params.state ?? ''
    issuerDid = ''
    valid = false
    disclosedClaims = {}
    throw new AppError('UNSUPPORTED_FORMAT', 'mdoc direct_post not yet wired — use SD-JWT', 501)
  }

  const session = await findVpSessionByNonce(nonce)
  if (!session) throw new AppError('INVALID_REQUEST', 'VP session nonce not found or expired', 400)

  const issuerTrusted = issuerDid ? await isIssuerTrusted(issuerDid) : false

  await updateVpSession(session.id as string, valid && issuerTrusted ? 'complete' : 'failed', {
    valid, disclosedClaims, issuerDid, issuerTrusted,
  })
}

export async function handleVpResult(sessionId: string) {
  const session = await findVpSession(sessionId)
  if (!session) throw new AppError('NOT_FOUND', 'VP session not found', 404)
  if (session.status === 'pending') return { status: 'pending' }
  return { status: session.status, result: session.result }
}
