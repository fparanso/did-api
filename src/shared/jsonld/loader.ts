// src/shared/jsonld/loader.ts
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { AppError } from '../errors.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const ALLOWED_CONTEXTS = new Map<string, string>([
  ['https://www.w3.org/ns/credentials/v2',               'credentials-v2.json'],
  ['https://w3id.org/security/data-integrity/v2',        'data-integrity-v2.json'],
  ['https://w3id.org/security/multikey/v1',              'multikey-v1.json'],
  ['https://w3id.org/security/suites/ed25519-2020/v1',   'ed25519-2020-v1.json'],
  ['https://www.w3.org/ns/did/v1',                       'did-v1.json'],
])

const contextCache = new Map<string, object>()
let didResolver: ((did: string) => Promise<object>) | null = null

export async function initContextLoader(): Promise<void> {
  const dir = join(__dirname, 'contexts')
  for (const [url, file] of ALLOWED_CONTEXTS) {
    const content = await Bun.file(join(dir, file)).text()
    contextCache.set(url, JSON.parse(content))
  }
}

export function setDidResolver(resolver: (did: string) => Promise<object>): void {
  didResolver = resolver
}

export function getDocumentLoader() {
  return async (url: string): Promise<{ contextUrl: null; document: object; documentUrl: string }> => {
    // Handle DID resolution
    if (url.startsWith('did:')) {
      const fragmentIdx = url.indexOf('#')
      const did = fragmentIdx >= 0 ? url.slice(0, fragmentIdx) : url
      const keyId = fragmentIdx >= 0 ? url.slice(fragmentIdx + 1) : null

      if (!didResolver) throw new Error('DID resolver not initialized')
      const didDoc = await didResolver(did)

      // If a fragment was requested, extract the specific verification method
      if (keyId) {
        const doc = didDoc as Record<string, unknown>
        const vms: object[] = Array.isArray(doc.verificationMethod)
          ? (doc.verificationMethod as object[])
          : []
        const vm = vms.find((m) => {
          const method = m as Record<string, unknown>
          return method.id === url || method.id === `#${keyId}`
        })
        if (vm) {
          // Return the verification method with the DID doc context so it can be expanded
          const vmWithContext = {
            '@context': (doc['@context'] as unknown) ?? [],
            ...(vm as Record<string, unknown>),
          }
          return { contextUrl: null, document: vmWithContext, documentUrl: url }
        }
      }

      return { contextUrl: null, document: didDoc, documentUrl: url }
    }
    // Handle known JSON-LD contexts
    const doc = contextCache.get(url)
    if (!doc) throw new AppError('INVALID_CONTEXT', `INVALID_CONTEXT: Unknown context: ${url}`, 422)
    return { contextUrl: null, document: doc, documentUrl: url }
  }
}
