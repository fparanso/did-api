// tests/unit/errors.test.ts
import { describe, test, expect } from 'bun:test'
import { AppError, Errors } from '../../src/shared/errors'

describe('AppError', () => {
  test('constructs with code, message, status', () => {
    const e = new AppError('TEST', 'test message', 400)
    expect(e.code).toBe('TEST')
    expect(e.message).toBe('test message')
    expect(e.status).toBe(400)
    expect(e instanceof Error).toBe(true)
  })
})

describe('Errors factory', () => {
  test('DID_NOT_FOUND returns 404', () => {
    const e = Errors.DID_NOT_FOUND('did:key:z6Mk')
    expect(e.status).toBe(404)
    expect(e.code).toBe('DID_NOT_FOUND')
  })

  test('INVALID_PROOF returns 422', () => {
    expect(Errors.INVALID_PROOF().status).toBe(422)
  })

  test('UNAUTHORIZED_ROLE returns 403', () => {
    expect(Errors.UNAUTHORIZED_ROLE().status).toBe(403)
  })

  test('CHALLENGE_EXPIRED returns 401', () => {
    expect(Errors.CHALLENGE_EXPIRED().status).toBe(401)
  })

  test('FORBIDDEN returns 403', () => {
    expect(Errors.FORBIDDEN().status).toBe(403)
  })
})
