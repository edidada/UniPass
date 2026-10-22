import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiFailure, get, isUuid, message, post } from './api'

const csrf = { header_name: 'X-CSRF-TOKEN', parameter_name: '_csrf', token: 'proof-token' }
const body = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })

describe('api client', () => {
  afterEach(() => { vi.unstubAllGlobals() })

  it('posts the header-delivered CSRF proof and forwards an idempotency key', async () => {
    // The client fetches /api/public/csrf first; the mock answers the CSRF path itself and
    // the post path as pre-typed call signatures: (path: string, init?: RequestInit).
    const fetcher = vi.fn(async (path: string, init?: RequestInit) =>
      path === '/api/public/csrf' ? body(csrf) : body({ ok: true }))
    vi.stubGlobal('fetch', fetcher)
    const result = await post<{ ok: boolean }>('/api/password/reset/request', { employee_no: 'E001' }, '6442eccc-9153-48c7-ae69-811ba6f75836')
    expect(result.ok).toBe(true)
    expect(fetcher.mock.calls.map(([path]) => path)).toEqual(['/api/public/csrf', '/api/password/reset/request'])
    const init = fetcher.mock.calls[1]![1] as RequestInit
    const headers = init.headers as Record<string, string>
    expect(headers['X-CSRF-TOKEN']).toBe('proof-token')
    expect(headers['Idempotency-Key']).toBe('6442eccc-9153-48c7-ae69-811ba6f75836')
    expect(headers['Content-Type']).toBe('application/json')
    expect(String(init.body)).toBe(JSON.stringify({ employee_no: 'E001' }))
    expect(init.credentials).toBe('same-origin')
    expect(init.redirect).toBe('error')
  })
  it('converts a JSON error carrying an operation id into a read-only recovery failure', async () => {
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) =>
      body({ error: 'DIRECTORY_REJECTED', detail: 'sensitive-details', operation_id: 'b530108c-fc07-4097-9866-34b19d2fe818' }, 409)))
    await expect(get('/api/password/operations/b530108c-fc07-4097-9866-34b19d2fe818')).rejects.toMatchObject({
      status: 409, code: 'DIRECTORY_REJECTED', operationId: 'b530108c-fc07-4097-9866-34b19d2fe818',
    })
  })
  it('never renders server-supplied error text or secrets', () => {
    expect(message(new ApiFailure(400, 'secret-server-detail'))).not.toContain('secret-server-detail')
    expect(message(new ApiFailure(400, 'POLICY_REJECTED'))).toContain('安全策略')
    expect(message(new ApiFailure(401))).toContain('重新登录')
    expect(message(new ApiFailure(0))).toContain('连接中断')
    expect(message(new ApiFailure(500))).toContain('服务暂不可用')
    expect(message(new Error('plain'))).not.toContain('plain')
  })
  it('rejects paths that are outside the API or carry a fragment before any CSRF proof is requested', async () => {
    const fetcher = vi.fn(async (path: string, init?: RequestInit) => body({ error: 'MUST_NOT_CALL' }))
    vi.stubGlobal('fetch', fetcher)
    // Path validation happens before the CSRF fetch, so a rejected target opens no session.
    await expect(post('/https://evil.example/api/x')).rejects.toMatchObject({ status: 400 })
    await expect(get('/api/password/operations/b530108c-fc07-4097-9866-34b19d2fe818#leak')).rejects.toMatchObject({ status: 400 })
    expect(fetcher).not.toHaveBeenCalled()
    await expect(post('/api/password/operations/b530108c-fc07-4097-9866-34b19d2fe818#leak')).rejects.toMatchObject({ status: 400 })
    expect(fetcher).not.toHaveBeenCalled()
  })
})
describe('uuid validation', () => {
  it('accepts only single canonical uuid strings', () => {
    expect(isUuid('b530108c-fc07-4097-9866-34b19d2fe818')).toBe(true)
    expect(isUuid('b530108cfc074097986634b19d2fe818')).toBe(false)
    expect(isUuid(['6442eccc-9153-48c7-ae69-811ba6f75836'])).toBe(false)
    expect(isUuid('../portal/continue')).toBe(false)
  })
})
