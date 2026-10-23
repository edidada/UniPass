<script setup lang="ts">
import { ref, watch } from 'vue'
import { assertCursor, get, isClientId, message, post } from '../api'
import type { AdminClientDetail, AdminClientListPage, AdminClientReview, AdminIssuedSecret } from '../api'
import { useAccount, useWipe } from '../flow'

const kinds = ['CONFIDENTIAL', 'NATIVE', 'SPA'] as const
const scopesAllowed = ['openid', 'profile', 'email', 'api.read'] as const
const { identity, error: accountError } = useAccount()
const clients = ref<AdminClientListPage['entries']>([]); const cursor = ref<string | null>(null)
const error = ref(''); const busy = ref(false); const notice = ref('')
const target = ref(''); const detail = ref<AdminClientDetail | null>(null); const detailBusy = ref(false)

// Registration/update form; every piece of one-time material lives only in these refs.
const clientId = ref(''); const name = ref(''); const kind = ref<'CONFIDENTIAL' | 'NATIVE' | 'SPA'>('CONFIDENTIAL')
const redirects = ref(''); const logoutRedirects = ref(''); const backchannelUri = ref('')
const scopes = ref<string[]>(['openid']); const owner = ref(''); const formError = ref(''); const formBusy = ref(false)
const secret = ref(''); const secretKeyId = ref(''); const overlapUntil = ref('')
const updateBusy = ref(false); const manageError = ref(''); const manageNotice = ref('')
const disableConfirm = ref(''); const overlapSeconds = ref('600'); const rotateBusy = ref(false)
const reason = ref('')

const canManage = () => !!identity.value?.roles?.some(role => role === 'ROLE_APP_ADMIN' || role === 'ROLE_SYSTEM_ADMIN')

// One-time material is wiped on pagehide and unmount; it never enters
// localStorage, URLs or notifications. Dismissal clears it explicitly.
function clearSecret(): void { secret.value = ''; secretKeyId.value = ''; overlapUntil.value = '' }
useWipe(secret, secretKeyId, overlapUntil)

function parsedLines(value: string): string[] {
  return value.split('\n').map(line => line.trim()).filter(line => line.length > 0)
}
function validateRedirects(values: string[]): boolean {
  return values.length > 0 && values.length <= 10 && new Set(values).size === values.length &&
    values.every(value => { try { return !new URL(value).hash && !new URL(value).username } catch { return false } })
}
function populateForm(entry: AdminClientDetail): void {
  name.value = entry.name; owner.value = entry.owner || ''
  redirects.value = entry.redirectUris.join('\n')
  logoutRedirects.value = entry.postLogoutRedirectUris.join('\n')
  backchannelUri.value = entry.backchannelUri || ''
  scopes.value = [...scopesAllowed].filter(scope => entry.scopes.includes(scope))
}
async function load(more = false) {
  if (busy.value) return
  busy.value = true; error.value = ''
  try {
    if (more) assertCursor(cursor.value)
    const page = await get<AdminClientListPage>('/api/admin/console/clients' + (more && cursor.value ? '?cursor=' + cursor.value : ''))
    clients.value = more ? [...clients.value, ...page.entries] : page.entries; cursor.value = page.nextCursor
  } catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
async function loadDetail() {
  detail.value = null
  if (!isClientId(target.value)) { if (target.value) manageError.value = '请输入有效的客户端编号。'; return }
  detailBusy.value = true; manageError.value = ''; manageNotice.value = ''; disableConfirm.value = ''
  try {
    const loaded = await get<AdminClientDetail>(`/api/admin/console/clients/${encodeURIComponent(target.value)}`)
    detail.value = loaded
    populateForm(loaded)
  } catch (failure) { detail.value = null; manageError.value = message(failure) } finally { detailBusy.value = false }
}
async function register() {
  if (formBusy.value || !canManage()) return
  clearSecret(); formError.value = ''; notice.value = ''
  const redirectsValue = parsedLines(redirects.value), logoutValue = parsedLines(logoutRedirects.value)
  if (!isClientId(clientId.value)) { formError.value = '请输入有效且唯一的客户端编号。'; return }
  if (!name.value.trim()) { formError.value = '请填写应用名称。'; return }
  if (!owner.value.trim()) { formError.value = "请填写负责人（responsible party）。"; return }
  if (!validateRedirects(redirectsValue) || (logoutValue.length > 0 && !validateRedirects(logoutValue))) { formError.value = '回调地址无效，请检查重复项、协议与数量。'; return }
  formBusy.value = true
  try {
    const issued = await post<AdminIssuedSecret>('/api/admin/console/clients/register', {
      client_id: clientId.value.trim(), name: name.value.trim(), kind: kind.value,
      redirect_uris: redirectsValue, post_logout_redirect_uris: logoutValue,
      scopes: [...scopesAllowed].filter(scope => scopes.value.includes(scope)), backchannel_logout_uri: backchannelUri.value || null,
      owner: owner.value.trim(), // responsible party is mandatory for managed registrations
    }, crypto.randomUUID())
    if (issued.replay) notice.value = '该密钥已此前发放且仅展示一次；如需新密钥请用新的幂等键重新注册轮换。'
    else { secret.value = issued.secret ?? ''; secretKeyId.value = issued.secretKeyId; overlapUntil.value = issued.overlapUntil ?? '' }
    formBusy.value = false
    await load()
  } catch (failure) { formBusy.value = false; formError.value = message(failure) }
}
async function saveUpdate() {
  if (!detail.value || updateBusy.value || !canManage()) return
  manageError.value = ''; manageNotice.value = ''
  const clientToMutate = detail.value
  const redirectsValue = parsedLines(redirects.value), logoutValue = parsedLines(logoutRedirects.value)
  if (!owner.value.trim() || !name.value.trim()) { manageError.value = '请填写名称与负责人后再保存。'; return }
  if (!validateRedirects(redirectsValue) || (logoutValue.length > 0 && !validateRedirects(logoutValue))) { manageError.value = '回调地址无效，请检查重复项、协议与数量。'; return }
  updateBusy.value = true
  try {
    detail.value = await post<AdminClientDetail>(`/api/admin/console/clients/${encodeURIComponent(clientToMutate.clientId)}/update`, {
      name: name.value.trim(), owner: owner.value.trim(), redirectUris: redirectsValue, postLogoutRedirectUris: logoutValue,
      scopes: [...scopesAllowed].filter(scope => scopes.value.includes(scope)), backchannelUri: backchannelUri.value || null,
    }, crypto.randomUUID())
    manageNotice.value = '已保存，可在审计记录中核对。'
  } catch (failure) { manageError.value = message(failure) } finally { updateBusy.value = false }
}
async function changeState(enable: boolean) {
  if (!detail.value || updateBusy.value || !canManage()) return
  manageError.value = ''; manageNotice.value = ''
  const clientToMutate = detail.value
  // Destructive action needs the operator to type the exact client id.
  if (!enable && disableConfirm.value !== clientToMutate.clientId) { manageError.value = '请在确认框中输入客户端编号后再禁用。'; return }
  if (!reason.value.trim()) { manageError.value = '请填写操作原因。'; return }
  updateBusy.value = true
  try {
    const review = await post<AdminClientReview>(`/api/admin/console/clients/${encodeURIComponent(clientToMutate.clientId)}/${enable ? 'enable' : 'disable'}`,
      { reason: reason.value.trim() }, crypto.randomUUID())
    detail.value = { ...clientToMutate, enabled: review.enabled }
    manageNotice.value = review.enabled ? '应用已启用；旧授权不会复活。' : '应用已禁用；其未完成令牌与回调任务已一并阻断。'
    reason.value = ''
  } catch (failure) { manageError.value = message(failure) } finally { updateBusy.value = false }
}
async function rotate() {
  if (!detail.value || rotateBusy.value || !canManage()) return
  manageError.value = ''; manageNotice.value = ''
  const overlap = Number(overlapSeconds.value)
  if (!Number.isInteger(overlap) || overlap < 0 || overlap > 3600) { manageError.value = '重叠窗口必须为 0–3600 秒。'; return }
  if (!reason.value.trim()) { manageError.value = '请填写操作原因。'; return }
  rotateBusy.value = true
  try {
    const issued = await post<AdminIssuedSecret>(`/api/admin/console/clients/${encodeURIComponent(detail.value.clientId)}/rotate-secret`,
      { overlapSeconds: overlap }, crypto.randomUUID())
    if (issued.replay) manageNotice.value = '轮换此前已完成，密钥仅展示一次；请用新的幂等键再次轮换以获取新密钥。'
    else { clearSecret(); secret.value = issued.secret ?? ''; secretKeyId.value = issued.secretKeyId; overlapUntil.value = issued.overlapUntil ?? '' }
    reason.value = ''
    await loadDetail()
  } catch (failure) { manageError.value = message(failure) } finally { rotateBusy.value = false }
}
function toggleScope(scope: string): void {
  scopes.value = scopes.value.includes(scope) ? scopes.value.filter(item => item !== scope) : [...scopes.value, scope]
}
watch(identity, value => { if (value && canManage()) void load() })
function stateLabel(enabled: boolean): string { return enabled ? '启用' : '禁用' }
</script>
<template>
  <header class="page-heading"><span class="eyebrow">应用管理</span><h1>注册与生命周期</h1><p>登记企业应用客户端，管理回调、负责人与密钥轮换。密钥只展示一次，禁用是破坏性操作。</p></header>
  <p v-if="accountError || error" role="alert" class="error">{{ accountError || error }}</p>
  <template v-if="identity && canManage()">
    <section class="card"><h2>应用列表</h2><p class="muted">不含任何密钥或口令字段；游标分页。</p>
      <ul class="session-list"><li v-for="client in clients" :key="client.clientId"><div><h3>{{ client.clientId }} <span class="badge" :class="client.enabled ? 'good' : ''">{{ stateLabel(client.enabled) }}</span></h3><p>{{ client.name }} · {{ client.kind }}<template v-if="client.owner"> · 负责人 {{ client.owner }}</template></p><p class="muted">{{ client.scopes?.length ? client.scopes.join('、') : '' }}</p></div><button class="secondary" type="button" @click="() => { target = client.clientId; void loadDetail(); }">查看</button></li></ul>
      <p v-if="busy" role="status">正在加载…</p><p v-else-if="!clients.length && !error">尚无已登记应用。</p><button v-if="cursor && !busy" class="secondary" @click="load(true)">加载更多应用</button>
    </section>
    <section class="card"><h2>登记新应用</h2><p class="muted">机密客户端将生成一次性密钥；地址策略与服务端一致，不允许重复或无效回调。</p>
      <form @submit.prevent="register">
        <p><label for="app-client-id">客户端编号</label><input id="app-client-id" v-model="clientId" autocomplete="off" spellcheck="false" required /></p>
        <p><label for="app-name">应用名称</label><input id="app-name" v-model="name" maxlength="200" required autocomplete="off" /></p>
        <p><label for="app-kind">类型</label><select id="app-kind" v-model="kind"><option v-for="option in kinds" :key="option" :value="option">{{ option }}</option></select></p>
        <p><label for="app-owner">负责人（责任方）</label><input id="app-owner" v-model="owner" maxlength="200" required autocomplete="off" /></p>
        <p><label for="app-redirects">回调地址（每行一条）</label><textarea id="app-redirects" v-model="redirects" autocomplete="off" required></textarea></p>
        <p><label for="app-logout-redirects">登出回调（每行一条，可选）</label><textarea id="app-logout-redirects" v-model="logoutRedirects" autocomplete="off"></textarea></p>
        <p><label for="app-backchannel">Backchannel 回调（机密客户端可选）</label><input id="app-backchannel" v-model="backchannelUri" autocomplete="off" /></p>
        <fieldset><legend>授权范围</legend><p v-for="scope in scopesAllowed" :key="scope"><label><input type="checkbox" :checked="scopes.includes(scope)" @change="toggleScope(scope)" /> {{ scope }}</label></p></fieldset>
        <div class="actions"><button type="submit" :disabled="formBusy">登记</button></div>
      </form>
      <div v-if="secret" class="card" data-testid="issued-secret"><h3>一次性密钥（{{ secretKeyId }}）</h3><p><code>{{ secret }}</code></p><p class="muted">仅本次展示，离开页面即清除；如已丢失请用新的幂等键重新轮换。<button type="button" class="secondary" @click="clearSecret">我已保存，立即清除</button></p></div>
      <p v-if="formBusy" role="status">正在处理…</p>
      <p v-if="formError" role="alert" class="error">{{ formError }}</p>
      <p v-if="notice" role="status" class="good">{{ notice }}</p>
    </section>
    <section class="card"><h2>查看与维护</h2>
      <p><label for="app-target">客户端编号</label><input id="app-target" v-model="target" autocomplete="off" spellcheck="false" placeholder="client-id" /></p>
      <div class="actions"><button class="secondary" type="button" :disabled="detailBusy" @click="loadDetail()">读取详情</button></div>
      <template v-if="detail">
        <ul class="session-list"><li><div><h3>{{ detail.clientId }} <span class="badge" :class="detail.enabled ? 'good' : ''">{{ stateLabel(detail.enabled) }}</span></h3><p>{{ detail.name }} · {{ detail.kind }} · 负责人 {{ detail.owner || '未登记' }}</p><p class="muted">回调：{{ detail.redirectUris.join('、') }}<template v-if="detail.postLogoutRedirectUris.length"> · 登出：{{ detail.postLogoutRedirectUris.join('、') }}</template></p><p class="muted">密钥标识：{{ detail.secretKeyId || '公钥客户端' }}<template v-if="detail.overlapUntil"> · 旧密钥窗口至 {{ new Date(detail.overlapUntil).toLocaleString() }}</template></p></div></li></ul>
        <p><label for="app-update-name">应用名称</label><input id="app-update-name" v-model="name" maxlength="200" autocomplete="off" /></p>
        <p><label for="app-update-owner">负责人（责任方）</label><input id="app-update-owner" v-model="owner" maxlength="200" autocomplete="off" /></p>
        <p><label for="app-update-redirects">回调地址（每行一条）</label><textarea id="app-update-redirects" v-model="redirects" autocomplete="off"></textarea></p>
        <p><label for="app-update-logout">登出回调（每行一条，可选）</label><textarea id="app-update-logout" v-model="logoutRedirects" autocomplete="off"></textarea></p>
        <p><label for="app-update-backchannel">Backchannel 回调（机密客户端可选）</label><input id="app-update-backchannel" v-model="backchannelUri" autocomplete="off" /></p>
        <fieldset><legend>授权范围</legend><p v-for="scope in scopesAllowed" :key="scope"><label><input type="checkbox" :checked="scopes.includes(scope)" @change="toggleScope(scope)" /> {{ scope }}</label></p></fieldset>
        <div class="actions"><button class="secondary" type="button" :disabled="updateBusy" @click="saveUpdate()">保存变更</button></div>
        <p><label for="app-state-reason">操作原因</label><textarea id="app-state-reason" v-model="reason" required maxlength="500" autocomplete="off"></textarea></p>
        <div class="actions">
          <button v-if="!detail.enabled" type="button" :disabled="updateBusy" @click="changeState(true)">启用应用</button>
          <template v-else><input v-model="disableConfirm" aria-label="输入客户端编号确认禁用" placeholder="输入客户端编号确认禁用" /><button class="secondary" type="button" :disabled="updateBusy" @click="changeState(false)">禁用应用</button></template>
          <button v-if="detail.confidential" type="button" :disabled="rotateBusy" @click="rotate()">轮换密钥（重叠 {{ overlapSeconds }} 秒）</button>
        </div>
        <p v-if="detail.confidential"><label for="app-overlap">重叠窗口（0–3600 秒）</label><input id="app-overlap" v-model="overlapSeconds" autocomplete="off" /></p>
        <p v-if="updateBusy || rotateBusy" role="status">正在处理…</p>
        <p v-if="manageError" role="alert" class="error">{{ manageError }}</p>
        <p v-if="manageNotice" role="status" class="good">{{ manageNotice }}</p>
      </template>
      <p v-else-if="target && !detailBusy">{{ manageError }}</p>
    </section>
  </template>
</template>
