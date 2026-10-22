import { onBeforeUnmount, onMounted, ref } from 'vue'
import type { Ref } from 'vue'
import { ApiFailure, get, isUuid, message, post } from './api'
import type { Identity, PasswordOperation } from './api'

export function continuation(): string | undefined {
  const values = new URLSearchParams(window.location.search).getAll('continue')
  return values.length === 1 && isUuid(values[0]) ? values[0] : undefined
}
export function withContinuation(path: string): string {
  const id = continuation(); return id ? `${path}?continue=${id}` : path
}
export function mfaFor(task: 'password' | 'sessions' | 'factors' | 'binding'): string {
  return continuation() ? withContinuation('/portal/mfa') : '/portal/mfa?task=' + task
}
export function useWipe(...fields: Ref<string>[]): void {
  const clear = () => { for (const field of fields) field.value = '' }
  onMounted(() => window.addEventListener('pagehide', clear))
  onBeforeUnmount(() => { clear(); window.removeEventListener('pagehide', clear) })
}
export function useAccount(auto = true) {
  const identity = ref<Identity>(); const error = ref(''); const loading = ref(true)
  const refresh = async () => {
    loading.value = true; error.value = ''
    try { identity.value = await get<Identity>('/api/session/me') }
    catch (failure) {
      if (failure instanceof ApiFailure && failure.status === 401) window.location.assign(withContinuation('/login'))
      error.value = message(failure)
    } finally { loading.value = false }
  }
  onMounted(() => { if (auto) void refresh(); else loading.value = false })
  return { identity, error, loading, refresh }
}
export function operationReference(): { operation?: string; request?: string } {
  const query = new URLSearchParams(window.location.search)
  const read = (name: string) => query.getAll(name).length === 1 && isUuid(query.get(name)) ? query.get(name)! : undefined
  return { operation: read('operation'), request: read('request') }
}
// Never retries a write. Only a non-secret owner/browser-bound reference survives reload.
export function usePasswordOperation(reset: boolean) {
  const initial = operationReference(); const result = ref<PasswordOperation>(); const error = ref('')
  const phase = ref<'idle' | 'submitting' | 'polling' | 'paused' | 'done'>('idle')
  let operation = initial.operation; let request = initial.request; let timer: ReturnType<typeof setTimeout> | undefined
  let alive = true; let reads = 0; const controller = new AbortController()
  const base = reset ? '/api/password/reset' : '/api/password'
  const remember = () => {
    const query = new URLSearchParams(window.location.search)
    query.delete('operation'); query.delete('request')
    if (operation) query.set('operation', operation); else if (request) query.set('request', request)
    window.history.replaceState(null, '', window.location.pathname + (query.size ? '?' + query.toString() : ''))
  }
  const accept = (value: PasswordOperation) => {
    if (!isUuid(value?.id) || !['PREPARED', 'UNKNOWN', 'COMMITTED', 'REJECTED'].includes(value?.state)) throw new ApiFailure(502)
    result.value = value; operation = value.id; remember()
    if (value.state === 'COMMITTED' || value.state === 'REJECTED') { phase.value = 'done'; return true }
    return false
  }
  const read = async () => {
    if (!alive || (!operation && !request)) return
    phase.value = 'polling'; error.value = ''; reads++
    try {
      const path = operation ? `${base}/operations/${operation}` : `${base}/requests/${request}/operation`
      const value = await get<PasswordOperation>(path, controller.signal)
      if (!alive) return
      if (accept(value)) return
    } catch (failure) {
      if (!alive) return
      error.value = failure instanceof ApiFailure && failure.status === 404 ? '处理记录尚未可查，请稍后查询，不要重新提交密码。' : message(failure)
      if (failure instanceof ApiFailure && [401, 403].includes(failure.status)) { phase.value = 'paused'; return }
    }
    if (reads >= 24) { phase.value = 'paused'; return }
    timer = setTimeout(() => void read(), 5000)
  }
  const submit = async (body: unknown) => {
    if (phase.value !== 'idle') return
    phase.value = 'submitting'; error.value = ''; request = crypto.randomUUID(); remember()
    try {
      const value = await post<PasswordOperation>(reset ? `${base}/confirm` : `${base}/change`, body, request)
      if (!alive || accept(value)) return
    } catch (failure) {
      if (!alive) return
      if (failure instanceof ApiFailure && failure.operationId) operation = failure.operationId
      if (failure instanceof ApiFailure && failure.status >= 400 && failure.status < 500 && !failure.operationId) {
        phase.value = 'idle'; request = undefined; remember(); error.value = message(failure); return
      }
      error.value = message(failure); remember()
    }
    if (alive) void read()
  }
  const check = () => { if (timer) clearTimeout(timer); reads = 0; void read() }
  onMounted(() => { if (operation || request) void read() })
  const stop = () => { alive = false; if (timer) clearTimeout(timer); controller.abort() }
  onMounted(() => window.addEventListener('pagehide', stop))
  onBeforeUnmount(() => { stop(); window.removeEventListener('pagehide', stop) })
  return { phase, result, error, submit, check, resuming: !!(initial.operation || initial.request) }
}

export function takeFragmentProof(location: Pick<Location, 'hash' | 'pathname' | 'search'>, history: Pick<History, 'replaceState'>): () => string | undefined {
  const query = new URLSearchParams(location.hash.slice(1)); const tokens = query.getAll('token')
  let proof = location.pathname === '/reset' && tokens.length === 1 && /^[A-Za-z0-9_-]{43}$/.test(tokens[0]!) ? tokens[0] : undefined
  if (location.hash) history.replaceState(null, '', location.pathname + location.search)
  return () => { const value = proof; proof = undefined; return value }
}
