import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import PasswordPage from './pages/PasswordPage.vue'
import ResetPage from './pages/ResetPage.vue'
import MfaPage from './pages/MfaPage.vue'
import SessionsPage from './pages/SessionsPage.vue'
import { message, ApiFailure } from './api'
import { takeFragmentProof } from './flow'

const operation = '6442eccc-9153-48c7-ae69-811ba6f75836'
const current = 'b530108c-fc07-4097-9866-34b19d2fe818'
const csrf = { header_name: 'X-CSRF-TOKEN', parameter_name: '_csrf', token: 'test-csrf-proof' }
const account = { sub: current, auth_epoch: 1, login_id: current, method: 'PASSWORD', authenticated_at: '2026-10-22T00:00:00Z', password_recent: true, must_change_password: false, mfa: { enrolled: false, required: false, recent: false, recovery_required: false } }
let wrappers: VueWrapper[] = []
const body = (value: unknown, status = 200) => new Response(status === 204 ? null : JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
function attach(component: Parameters<typeof mount>[0], options: Record<string, unknown> = {}) {
  const wrapper = mount(component, { attachTo: document.body, ...options }); wrappers.push(wrapper); return wrapper
}
beforeEach(() => {
  window.history.replaceState(null, '', '/portal/password'); localStorage.clear(); sessionStorage.clear()
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
})
afterEach(() => { wrappers.forEach(wrapper => wrapper.unmount()); wrappers = []; vi.useRealTimers(); vi.unstubAllGlobals(); document.body.innerHTML = '' })
async function fillPassword(wrapper: VueWrapper) {
  await flushPromises()
  await wrapper.get('#old-password').setValue('old-test-password')
  await wrapper.get('#new-password').setValue('new-test-password')
  await wrapper.get('#confirm-password').setValue('new-test-password')
  await wrapper.get('form').trigger('submit'); await flushPromises()
}
describe('password operation recovery', () => {
  it('polls a 202 result without repeating the password write and removes inputs', async () => {
    const writes: RequestInit[] = []; let committed = false
    vi.stubGlobal('fetch', vi.fn(async (path: string, init: RequestInit) => {
      if (path === '/api/session/me') return body(account)
      if (path === '/api/public/csrf') return body(csrf)
      if (path === '/api/password/change') { writes.push(init); return body({ id: operation, state: 'UNKNOWN' }, 202) }
      return body({ id: operation, state: committed ? 'COMMITTED' : 'UNKNOWN' })
    }))
    const wrapper = attach(PasswordPage); await fillPassword(wrapper)
    expect(writes).toHaveLength(1); expect(wrapper.find('input[type=password]').exists()).toBe(false)
    expect(window.location.search).toContain('operation=' + operation)
    await vi.advanceTimersByTimeAsync(10000); await flushPromises(); expect(writes).toHaveLength(1)
    committed = true; await vi.advanceTimersByTimeAsync(5000); await flushPromises()
    expect(wrapper.text()).toContain('密码已更新'); expect(writes).toHaveLength(1)
    expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it('recovers a lost response by the original request key without replaying credentials', async () => {
    const calls: string[] = []; let key = ''
    vi.stubGlobal('fetch', vi.fn(async (path: string, init: RequestInit) => {
      calls.push(path)
      if (path === '/api/session/me') return body(account)
      if (path === '/api/public/csrf') return body(csrf)
      if (path === '/api/password/change') { key = (init.headers as Record<string, string>)['Idempotency-Key']!; throw new TypeError('network failure') }
      return body({ id: operation, state: 'UNKNOWN' })
    }))
    const wrapper = attach(PasswordPage); await fillPassword(wrapper)
    expect(calls).toContain(`/api/password/requests/${key}/operation`)
    expect(calls.filter(path => path === '/api/password/change')).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(10000); await flushPromises()
    expect(calls.filter(path => path === '/api/password/change')).toHaveLength(1)
    expect(wrapper.text()).not.toContain('new-test-password')
  })
  it('resumes after refresh using reads only and does not invalidate the recovery session with /me', async () => {
    window.history.replaceState(null, '', '/portal/password?request=' + current)
    const calls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (path: string) => { calls.push(path); return body({ id: operation, state: 'COMMITTED' }) }))
    const wrapper = attach(PasswordPage); await flushPromises()
    expect(calls).toEqual([`/api/password/requests/${current}/operation`]); expect(wrapper.text()).toContain('密码已更新')
  })
  it('stops bounded missing-result polling and permits only another read', async () => {
    window.history.replaceState(null, '', '/portal/password?request=' + current)
    const fetcher = vi.fn(async () => body({ error: 'NOT_FOUND' }, 404)); vi.stubGlobal('fetch', fetcher)
    const wrapper = attach(PasswordPage); await flushPromises(); await vi.advanceTimersByTimeAsync(125000); await flushPromises()
    expect(fetcher).toHaveBeenCalledTimes(24); expect(wrapper.text()).toContain('重新查询结果')
    await vi.advanceTimersByTimeAsync(50000); expect(fetcher).toHaveBeenCalledTimes(24)
    await wrapper.get('button').trigger('click'); await flushPromises(); expect(fetcher).toHaveBeenCalledTimes(25)
  })
  it('clears rejected password inputs and does not expose response details', async () => {
    let writes = 0
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/session/me') return body(account)
      if (path === '/api/public/csrf') return body(csrf)
      writes++; return body({ error: 'POLICY_REJECTED', detail: 'sensitive-directory-detail' }, 400)
    }))
    const wrapper = attach(PasswordPage); await fillPassword(wrapper)
    expect(wrapper.text()).toContain('新密码未满足安全策略')
    expect(wrapper.text()).not.toContain('sensitive-directory-detail')
    for (const input of wrapper.findAll('input[type=password]')) expect((input.element as HTMLInputElement).value).toBe('')
    await vi.advanceTimersByTimeAsync(20000); expect(writes).toBe(1); expect(window.location.search).toBe('')
  })
})
describe('email proof and identity verification', () => {
  it('removes the proof fragment immediately and consumes its in-memory value once', () => {
    const replaceState = vi.fn(); const proof = 'x'.repeat(43)
    const take = takeFragmentProof({ pathname: '/reset', search: '', hash: '#token=' + proof }, { replaceState })
    expect(replaceState).toHaveBeenCalledWith(null, '', '/reset'); expect(take()).toBe(proof); expect(take()).toBeUndefined()
    expect(takeFragmentProof({ pathname: '/reset', search: '', hash: '#token=' + proof + '&token=' + proof }, { replaceState })()).toBeUndefined()
    expect(takeFragmentProof({ pathname: '/login', search: '', hash: '#token=' + proof }, { replaceState })()).toBeUndefined()
  })
  it('does not consume an email proof until an explicit verification click', async () => {
    window.history.replaceState(null, '', '/reset'); const calls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (path: string) => { calls.push(path); return path === '/api/public/csrf' ? body(csrf) : body({ reset_token: 'g'.repeat(43) }) }))
    const wrapper = attach(ResetPage, { global: { provide: { 'reset-proof': () => 'p'.repeat(43) } } }); await flushPromises()
    expect(calls).toEqual([]); expect(wrapper.text()).not.toContain('p'.repeat(43))
    await wrapper.get('button').trigger('click'); await flushPromises()
    expect(calls).toEqual(['/api/public/csrf', '/api/password/reset/verify']); expect(wrapper.text()).toContain('设置新密码')
    expect(wrapper.html()).not.toContain('g'.repeat(43)); expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it('uses a fresh session-bound challenge for OTP and clears the code before waiting', async () => {
    let verified = false; const calls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      calls.push(path)
      if (path === '/api/session/me') return body({ ...account, mfa: { ...account.mfa, enrolled: true, required: true, recent: verified } })
      if (path === '/api/public/csrf') return body(csrf)
      if (path === '/api/mfa/context') return body({ context: current })
      if (path === '/api/mfa/challenges') return body({ challenge: operation })
      verified = true; return body({ verified: true })
    }))
    const wrapper = attach(MfaPage); await flushPromises(); await wrapper.get('#otp').setValue('123456'); await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(calls.filter(path => path.startsWith('/api/mfa/'))).toEqual(['/api/mfa/context', '/api/mfa/challenges', '/api/mfa/verify'])
    expect(wrapper.text()).toContain('验证已完成'); expect(wrapper.html()).not.toContain('123456')
  })
  it('does not expose arbitrary server error content', () => {
    expect(message(new ApiFailure(400, 'secret-from-server'))).not.toContain('secret-from-server')
  })
})
it('loads later login pages and waits for confirmation before revoking', async () => {
  const writes: string[] = []; const calls: string[] = []
  const entry = (id: string, here: boolean) => ({ id, current: here, device: 'Chrome / Windows', method: 'PASSWORD', authenticatedAt: '2026-10-22T00:00:00Z', lastAccessAt: '2026-10-22T00:00:00Z' })
  vi.stubGlobal('fetch', vi.fn(async (path: string, init: RequestInit) => {
    calls.push(path)
    if (path === '/api/session/me') return body(account)
    if (path === '/api/public/csrf') return body(csrf)
    if (init.method === 'POST') { writes.push(path); return body(undefined, 204) }
    return path.includes('?before=') ? body({ entries: [entry(current, true)], nextCursor: null }) : body({ entries: [entry(operation, false)], nextCursor: operation })
  }))
  const wrapper = attach(SessionsPage); await flushPromises()
  const more = wrapper.findAll('button').find(button => button.text() === '加载更多登录')!; await more.trigger('click'); await flushPromises()
  expect(calls).toContain('/api/session/logins?before=' + operation); expect(wrapper.text()).toContain('当前登录')
  await wrapper.get('.session-list button').trigger('click'); await flushPromises(); expect(writes).toEqual([])
  await wrapper.findAll('button').find(button => button.text() === '取消')!.trigger('click'); expect(writes).toEqual([])
  await wrapper.get('.session-list button').trigger('click'); await wrapper.get('.danger').trigger('click'); await flushPromises()
  expect(writes).toEqual([`/api/session/logins/${operation}/revoke`]); expect(wrapper.findAll('.session-list li')).toHaveLength(1)
})
