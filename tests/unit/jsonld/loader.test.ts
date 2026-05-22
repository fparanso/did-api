// tests/unit/jsonld/loader.test.ts
import { describe, test, expect, beforeAll } from 'bun:test'
import { initContextLoader, getDocumentLoader, setDidResolver } from '../../../src/shared/jsonld/loader'

describe('context loader', () => {
  beforeAll(async () => {
    await initContextLoader()
  })

  test('loads a known context by URL', async () => {
    const loader = getDocumentLoader()
    const result = await loader('https://www.w3.org/ns/credentials/v2')
    expect(result.document).toBeTruthy()
    expect(result.contextUrl).toBeNull()
    expect(result.documentUrl).toBe('https://www.w3.org/ns/credentials/v2')
  })

  test('throws INVALID_CONTEXT for unknown URL', async () => {
    const loader = getDocumentLoader()
    await expect(loader('https://evil.example/bad-context')).rejects.toThrow('INVALID_CONTEXT')
  })

  test('resolves DID via resolver', async () => {
    setDidResolver(async (did) => ({ id: did, '@context': 'https://www.w3.org/ns/did/v1' }))
    const loader = getDocumentLoader()
    const result = await loader('did:key:z6MkTest')
    expect((result.document as any).id).toBe('did:key:z6MkTest')
  })
})
