import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import ClientsPage from './pages/ClientsPage.vue'

const appAdmin = { sub: '6442eccc-9153-48c7-ae69-811ba6f75836', auth_epoch: 1, login_id: '6442eccc-9153-48c7-ae69-811ba6f75836', method: 'PASSWORD', authenticated_at: '2026-10-24T00:00:00Z', password_recent: true, must_change_password: false, roles: ['ROLE_ADMIN_APP'], mfa: { enrolled: false, required: false, recent: false, recovery_required: false } }
const plain = { ...appAdmin, roles: ['ROLE_USER'] }
const auditor = { ...appAdmin, roles: ['ROLE_ADMIN_AUDIT'] }
const csrf = { header_name: 'X-CSRF-TOKEN', parameter_name: '_csrf', token: 'client-csrf-proof' }
const confidential = { id: 'c1', clientId: 'crm', name: 'CRM', kind: 'CONFIDENTIAL', enabled: true, redirectUris: ['https://crm.example/cb'], postLogoutRedirectUris: [], scopes: ['api.read', 'openid'], backchannelLogoutUri: '', issuedAt: '2026-10-24T00:00:00Z' }
const native = { ...confidential, id: 'c2', clientId: 'mobile', name: 'Mobile', kind: 'NATIVE' }
let wrappers: VueWrapper[] = []
const body = (value: unknown, status = 200) => new Response(status === 204 ? null : JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
function attach(): VueWrapper {
  const wrapper = mount(ClientsPage); wrappers.push(wrapper); return wrapper
}
afterEach(() => { wrappers.forEach(wrapper => wrapper.unmount()); wrappers = []; vi.unstubAllGlobals(); document.body.innerHTML = '' })

describe('application management', () => {
  it('does not read application data without an app administrator role', async () => {
    const fetcher = vi.fn(async (path: string) => path === '/api/session/me' ? body(plain) : body({ error: 'MUST_NOT_CALL' }))
    vi.stubGlobal('fetch', fetcher)
    const wrapper = attach(); await flushPromises()
    expect(wrapper.text()).toContain('没有应用管理权限')
    expect(fetcher.mock.calls.filter(([path]) => String(path).startsWith('/api/admin/console/clients'))).toHaveLength(0)
  })

  it('lists registered applications and only offers rotation for confidential clients', async () => {
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/session/me') return body(appAdmin)
      if (path === '/api/admin/console/clients') return body([confidential, native])
      return body({ error: 'MUST_NOT_CALL' })
    }))
    const wrapper = attach(); await flushPromises()
    expect(wrapper.text()).toContain('CRM')
    expect(wrapper.text()).toContain('Mobile')
    const rotateButtons = wrapper.findAll('button').filter(button => button.text() === '轮换密钥')
    expect(rotateButtons).toHaveLength(2)
    expect(rotateButtons[0]!.attributes('disabled')).toBeUndefined()
    expect(rotateButtons[1]!.attributes('disabled')).toBeDefined()
  })

  it('registers an application and renders the one-time secret only until dismissed', async () => {
    let posted: Record<string, unknown> = {}
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/session/me') return body(appAdmin)
      if (path === '/api/public/csrf') return body(csrf)
      if (path === '/api/admin/console/clients' && init?.method === 'POST') {
        posted = JSON.parse(String(init.body)) as Record<string, unknown>
        return body({ id: 'c1', clientId: 'crm', secret: 'A'.repeat(43), previousSecretValidUntil: null })
      }
      if (path === '/api/admin/console/clients') return body([])
      return body({ error: 'MUST_NOT_CALL' })
    }))
    const wrapper = attach(); await flushPromises()
    await wrapper.get('#client-id').setValue('crm')
    await wrapper.get('#client-name').setValue('CRM')
    await wrapper.get('#client-redirects').setValue('https://crm.example/cb\n\nhttps://crm.example/alt')
    await wrapper.get('#client-reason').setValue('开通新业务')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(posted.client_id).toBe('crm')
    expect(posted.redirect_uris).toEqual(['https://crm.example/cb', 'https://crm.example/alt'])
    expect(posted.kind).toBe('CONFIDENTIAL')
    expect(wrapper.text()).toContain('A'.repeat(43))
    await wrapper.findAll('button').find(button => button.text() === '我已妥善保存')!.trigger('click')
    expect(wrapper.text()).not.toContain('A'.repeat(43))
  })

  it('disables an application with a reason, exact id confirmation and a private idempotency key', async () => {
    let postedPath = ''; let postedBody: Record<string, unknown> = {}; let postedKey = ''; let enabled = true
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/session/me') return body(appAdmin)
      if (path === '/api/public/csrf') return body(csrf)
      if (path.endsWith('/state') && init?.method === 'POST') {
        postedPath = path; postedBody = JSON.parse(String(init.body)) as Record<string, unknown>
        postedKey = (init.headers as Record<string, string>)['Idempotency-Key']!
        enabled = false; return body(null, 204)
      }
      if (path === '/api/admin/console/clients') return body([{ ...confidential, enabled }])
      return body({ error: 'MUST_NOT_CALL' })
    }))
    const wrapper = attach(); await flushPromises()
    await wrapper.findAll('button').find(button => button.text() === '停用')!.trigger('click')
    await wrapper.get(`input[aria-label="停用 crm 的原因"]`).setValue('疑似泄露')
    // Confirm is disabled until the exact client id is typed.
    const confirm = wrapper.findAll('button').find(button => button.text() === '确认停用')!
    expect(confirm.attributes('disabled')).toBeDefined()
    await wrapper.get(`input[aria-label="输入 crm 以确认停用"]`).setValue('crm')
    expect(confirm.attributes('disabled')).toBeUndefined()
    await confirm.trigger('click')
    await flushPromises()
    expect(postedPath).toBe('/api/admin/console/clients/crm/state')
    expect(postedBody).toEqual({ enabled: false, reason: '疑似泄露' })
    expect(postedKey).toMatch(/^[0-9a-f-]{36}$/)
    expect(wrapper.text()).toContain('应用已停用')
    expect(wrapper.text()).toContain('已停用')
  })

  it('deletes an application only after an exact id confirmation and a reason, then removes it from the list', async () => {
    let postedPath = ''; let postedBody: Record<string, unknown> = {}; let postedKey = ''
    let list = [confidential, native]
    const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/session/me') return body(appAdmin)
      if (path === '/api/public/csrf') return body(csrf)
      if (path.endsWith('/delete') && init?.method === 'POST') {
        postedPath = path; postedBody = JSON.parse(String(init.body)) as Record<string, unknown>
        postedKey = (init.headers as Record<string, string>)['Idempotency-Key']!
        list = list.filter(item => item.clientId !== 'crm')
        return body(null, 204)
      }
      if (path === '/api/admin/console/clients') return body(list)
      return body({ error: 'MUST_NOT_CALL' })
    })
    vi.stubGlobal('fetch', fetcher)
    const wrapper = attach(); await flushPromises()
    const deleteButtons = wrapper.findAll('button').filter(button => button.text() === '删除应用')
    expect(deleteButtons).toHaveLength(2)
    await deleteButtons[0]!.trigger('click')
    await wrapper.get(`input[aria-label="删除 crm 的原因"]`).setValue('不再需要')
    const confirm = wrapper.findAll('button').find(button => button.text() === '确认删除')!
    // Confirm is locked until the exact client id is typed.
    expect(confirm.attributes('disabled')).toBeDefined()
    await wrapper.get(`input[aria-label="输入 crm 以确认删除"]`).setValue('wrong')
    expect(confirm.attributes('disabled')).toBeDefined()
    // While the confirmation id is wrong no delete request may leave the page.
    expect(fetcher.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'POST')).toHaveLength(0)
    await wrapper.get(`input[aria-label="输入 crm 以确认删除"]`).setValue('crm')
    expect(confirm.attributes('disabled')).toBeUndefined()
    await confirm.trigger('click'); await flushPromises()
    expect(postedPath).toBe('/api/admin/console/clients/crm/delete')
    expect(postedBody).toEqual({ reason: '不再需要' })
    expect(postedKey).toMatch(/^[0-9a-f-]{36}$/)
    // The deleted application is gone from the list and no one-time secret surfaced.
    expect(wrapper.text()).not.toContain('CRM')
    expect(wrapper.find('[data-testid="issued-secret"]').exists()).toBe(false)
    const leakedFrom = (storage: Storage | undefined) => storage ? Object.keys(storage).some(k => (storage.getItem(k) ?? '').includes('A'.repeat(43))) : false
    expect(leakedFrom(typeof localStorage !== 'undefined' ? localStorage : undefined)).toBe(false)
    expect(leakedFrom(typeof sessionStorage !== 'undefined' ? sessionStorage : undefined)).toBe(false)
  })

  it('does not disable when the confirmation id does not match the client id', async () => {
    const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/session/me') return body(appAdmin)
      if (path === '/api/public/csrf') return body(csrf)
      if (path === '/api/admin/console/clients') return body([confidential])
      return body({ error: 'MUST_NOT_CALL' })
    })
    vi.stubGlobal('fetch', fetcher)
    const wrapper = attach(); await flushPromises()
    await wrapper.findAll('button').find(button => button.text() === '停用')!.trigger('click')
    await wrapper.get(`input[aria-label="停用 crm 的原因"]`).setValue('疑似泄露')
    await wrapper.get(`input[aria-label="输入 crm 以确认停用"]`).setValue('wrong-id')
    await wrapper.findAll('button').find(button => button.text() === '确认停用')!.trigger('click')
    await flushPromises()
    expect(fetcher.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'POST')).toHaveLength(0)
  })

  it('rejects an invalid client identifier before any registration request', async () => {
    const fetcher = vi.fn(async (path: string, _init?: RequestInit) => path === '/api/session/me' ? body(appAdmin) : body([]))
    vi.stubGlobal('fetch', fetcher)
    const wrapper = attach(); await flushPromises()
    await wrapper.get('#client-id').setValue('../evil')
    await wrapper.get('#client-reason').setValue('测试原因')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(wrapper.text()).toContain('客户端编号')
    expect(fetcher.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'POST')).toHaveLength(0)
  })

  it('auditor sees no client management surface and issues no admin request', async () => {
    const fetcher = vi.fn(async (path: string) => path === '/api/session/me' ? body(auditor) : body({ error: 'MUST_NOT_CALL' }))
    vi.stubGlobal('fetch', fetcher)
    const wrapper = attach(); await flushPromises()
    expect(wrapper.text()).toContain('没有应用管理权限')
    expect(fetcher.mock.calls.filter(([path]) => String(path).startsWith('/api/admin/console/clients'))).toHaveLength(0)
  })

  it('rejects duplicate callback URIs before any registration request', async () => {
    const fetcher = vi.fn(async (path: string, _init?: RequestInit) => path === '/api/session/me' ? body(appAdmin) : body([]))
    vi.stubGlobal('fetch', fetcher)
    const wrapper = attach(); await flushPromises()
    await wrapper.get('#client-id').setValue('crm')
    await wrapper.get('#client-name').setValue('CRM')
    await wrapper.get('#client-redirects').setValue('https://crm.example/cb\nhttps://crm.example/cb')
    await wrapper.get('#client-reason').setValue('测试原因')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(wrapper.text()).toContain('回调地址')
    expect(fetcher.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'POST')).toHaveLength(0)
  })

  it('rejects a registration without a responsible-party name', async () => {
    const fetcher = vi.fn(async (path: string, _init?: RequestInit) => path === '/api/session/me' ? body(appAdmin) : body([]))
    vi.stubGlobal('fetch', fetcher)
    const wrapper = attach(); await flushPromises()
    await wrapper.get('#client-id').setValue('crm')
    await wrapper.get('#client-redirects').setValue('https://crm.example/cb')
    await wrapper.get('#client-reason').setValue('测试原因')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(wrapper.text()).toContain('显示名称')
    expect(fetcher.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'POST')).toHaveLength(0)
  })

  it('shows the one-time secret once, clears it on dismiss, and never leaks it to storage', async () => {
    const secret = 'A'.repeat(43)
    const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/session/me') return body(appAdmin)
      if (path === '/api/public/csrf') return body(csrf)
      if (path === '/api/admin/console/clients' && init?.method === 'POST') {
        const posts = fetcher.mock.calls.filter(c => c[0] === path && (c[1] as RequestInit | undefined)?.method === 'POST')
        // A replay of the same registration returns a conflict without re-exposing the secret.
        if (posts.length > 1)
          return new Response(JSON.stringify({ error: '密钥已签发，请勿重复提交' }), { status: 409, headers: { 'Content-Type': 'application/json' } })
        return body({ id: 'c1', clientId: 'crm', secret, previousSecretValidUntil: null })
      }
      if (path === '/api/admin/console/clients') return body([])
      return body({ error: 'MUST_NOT_CALL' })
    })
    vi.stubGlobal('fetch', fetcher)
    const wrapper = attach(); await flushPromises()
    await wrapper.get('#client-id').setValue('crm')
    await wrapper.get('#client-name').setValue('CRM')
    await wrapper.get('#client-redirects').setValue('https://crm.example/cb')
    await wrapper.get('#client-reason').setValue('开通新业务')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    // The secret is shown exactly once, equal to the cleartext issued by the server.
    expect(wrapper.get('[data-testid="issued-secret"]').text()).toBe(secret)
    const leakedFrom = (storage: Storage | undefined) => storage ? Object.keys(storage).some(k => (storage.getItem(k) ?? '').includes(secret)) : false
    expect(leakedFrom(typeof localStorage !== 'undefined' ? localStorage : undefined)).toBe(false)
    expect(leakedFrom(typeof sessionStorage !== 'undefined' ? sessionStorage : undefined)).toBe(false)
    // Manual dismiss clears the one-time secret from the UI immediately.
    await wrapper.findAll('button').find(button => button.text() === '我已妥善保存')!.trigger('click'); await flushPromises()
    expect(wrapper.find('[data-testid="issued-secret"]').exists()).toBe(false)
    // Replay to a conflict: submitting again clears the card (new submission wipes the
    // issued secret) and the conflict prompt must never re-expose the secret.
    await wrapper.get('#client-id').setValue('crm')
    await wrapper.get('#client-name').setValue('CRM')
    await wrapper.get('#client-redirects').setValue('https://crm.example/cb')
    await wrapper.get('#client-reason').setValue('开通新业务')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(wrapper.find('[role="alert"]').text()).not.toContain(secret)
    expect(wrapper.find('[data-testid="issued-secret"]').exists()).toBe(false)
  })
})
