<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { get, isClientId, message, post, put } from '../api'
import type { ClientSummary, IssuedClientSecret } from '../api'
import { useAccount } from '../flow'

const { identity, error: accountError } = useAccount()
const clients = ref<ClientSummary[]>([]); const error = ref(''); const busy = ref(false); const notice = ref('')
const issued = ref<IssuedClientSecret>()
const clientId = ref(''); const name = ref(''); const kind = ref<'CONFIDENTIAL' | 'NATIVE' | 'SPA'>('CONFIDENTIAL')
const redirects = ref(''); const logoutRedirects = ref(''); const backchannel = ref(''); const reason = ref('')
const rotateTarget = ref(''); const rotateReason = ref('')
const stateTarget = ref(''); const stateReason = ref(''); const stateConfirm = ref('')
const deleteTarget = ref(''); const deleteReason = ref(''); const deleteConfirm = ref('')
const editTarget = ref(''); const editName = ref(''); const editRedirects = ref(''); const editLogout = ref(''); const editBackchannel = ref(''); const editReason = ref('')
const isOperator = () => identity.value?.roles?.some(role => role === 'ROLE_SYSTEM_ADMIN' || role === 'ROLE_ADMIN_APP') ?? false

function onPageHide() { issued.value = undefined }

async function load() {
  if (busy.value) return
  busy.value = true; error.value = ''
  try { clients.value = await get<ClientSummary[]>('/api/admin/console/clients') }
  catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
watch(identity, value => { if (value) {
  if (isOperator()) void load(); else error.value = '此账户没有应用管理权限。'
} })
function lines(value: string): string[] {
  return value.split('\n').map(line => line.trim()).filter(line => line.length > 0)
}
async function register() {
  if (busy.value) return
  if (!isClientId(clientId.value)) { error.value = '客户端编号只能包含字母、数字、下划线、点与连字符，长度 3–100。'; return }
  if (!name.value.trim()) { error.value = '请填写应用显示名称（负责人）。'; return }
  const redirectList = lines(redirects.value)
  if (new Set(redirectList).size !== redirectList.length) { error.value = '回调地址不能重复。'; return }
  if (!reason.value.trim()) { error.value = '请填写登记原因。'; return }
  busy.value = true; error.value = ''; notice.value = ''; issued.value = undefined
  try {
    issued.value = await post<IssuedClientSecret>('/api/admin/console/clients', {
      client_id: clientId.value, name: name.value.trim(), kind: kind.value,
      redirect_uris: redirectList, post_logout_redirect_uris: lines(logoutRedirects.value),
      scopes: ['openid', 'profile', 'email', 'api.read'], backchannel_logout_uri: backchannel.value.trim() || null,
      reason: reason.value.trim(),
    })
    notice.value = '应用已登记。密钥仅显示一次，请立即交付。'
    clientId.value = ''; name.value = ''; redirects.value = ''; logoutRedirects.value = ''; backchannel.value = ''; reason.value = ''
    await load()
  } catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
async function rotate() {
  if (busy.value || !rotateTarget.value) return
  if (!rotateReason.value.trim()) { error.value = '请填写轮换原因。'; return }
  busy.value = true; error.value = ''; notice.value = ''
  try {
    issued.value = await post<IssuedClientSecret>(`/api/admin/console/clients/${rotateTarget.value}/rotate`,
      { reason: rotateReason.value.trim() }, crypto.randomUUID())
    notice.value = '密钥已轮换。旧密钥仅在显示的有效期内可用。'
    rotateTarget.value = ''; rotateReason.value = ''
    await load()
  } catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
function dismiss() { issued.value = undefined }
function beginEdit(client: ClientSummary) {
  editTarget.value = client.clientId; editName.value = client.name
  editRedirects.value = client.redirectUris.join('\n'); editLogout.value = client.postLogoutRedirectUris.join('\n')
  editBackchannel.value = client.backchannelLogoutUri ?? ''; editReason.value = ''; notice.value = ''
}
async function saveEdit() {
  if (busy.value || !editTarget.value) return
  if (!editReason.value.trim()) { error.value = '请填写修改原因。'; return }
  busy.value = true; error.value = ''; notice.value = ''
  try {
    await put(`/api/admin/console/clients/${editTarget.value}`, {
      client_id: editTarget.value, name: editName.value, kind: clients.value.find(item => item.clientId === editTarget.value)?.kind,
      redirect_uris: lines(editRedirects.value), post_logout_redirect_uris: lines(editLogout.value),
      scopes: clients.value.find(item => item.clientId === editTarget.value)?.scopes ?? ['openid'],
      backchannel_logout_uri: editBackchannel.value.trim() || null, reason: editReason.value.trim(),
    })
    notice.value = '应用配置已更新。'; editTarget.value = ''; await load()
  } catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
async function toggleState(client: ClientSummary) {
  if (busy.value || stateTarget.value !== client.clientId) return
  if (!stateReason.value.trim()) { error.value = '请填写停用或启用原因。'; return }
  busy.value = true; error.value = ''; notice.value = ''
  try {
    await post(`/api/admin/console/clients/${client.clientId}/state`,
      { enabled: !client.enabled, reason: stateReason.value.trim() }, crypto.randomUUID())
    notice.value = client.enabled ? '应用已停用，关联授权已被撤销。' : '应用已重新启用。'
    stateTarget.value = ''; stateReason.value = ''; stateConfirm.value = ''; await load()
  } catch (failure) { error.value = message(failure) } finally { busy.value = false; stateConfirm.value = '' }
}
async function remove(client: ClientSummary) {
  if (busy.value || deleteTarget.value !== client.clientId) return
  if (!deleteReason.value.trim()) { error.value = '请填写删除原因。'; return }
  busy.value = true; error.value = ''; notice.value = ''
  try {
    await post(`/api/admin/console/clients/${client.clientId}/delete`,
      { reason: deleteReason.value.trim() }, crypto.randomUUID())
    notice.value = '应用已删除，删除不可恢复。'
    deleteTarget.value = ''; deleteReason.value = ''; deleteConfirm.value = ''
    clients.value = clients.value.filter(item => item.clientId !== client.clientId)
  } catch (failure) { error.value = message(failure) } finally { busy.value = false; deleteConfirm.value = '' }
}
onMounted(() => window.addEventListener('pagehide', onPageHide))
onBeforeUnmount(() => { window.removeEventListener('pagehide', onPageHide); dismiss() })
</script>
<template>
  <header class="page-heading"><span class="eyebrow">管理控制台</span><h1>应用与密钥</h1><p>登记 OAuth 应用并轮换机密客户端密钥。所有操作都会留痕。</p></header>
  <p v-if="accountError || error" role="alert" class="error">{{ accountError || error }}</p>
  <template v-if="identity && isOperator()">
    <p v-if="notice" role="status" class="good">{{ notice }}</p>
    <section v-if="issued" class="card" aria-labelledby="issued-title"><h2 id="issued-title">一次性密钥</h2>
      <p>应用 <strong>{{ issued.clientId }}</strong> 的新密钥如下，关闭或刷新后不可再次查看：</p>
      <p><code class="secret" data-testid="issued-secret">{{ issued.secret ?? '（公共客户端无密钥）' }}</code></p>
      <p v-if="issued.previousSecretValidUntil" class="muted">旧密钥仍可使用至 {{ new Date(issued.previousSecretValidUntil).toLocaleString() }}。</p>
      <button class="secondary" @click="dismiss">我已妥善保存</button>
    </section>
    <section class="card"><h2>已登记应用</h2>
      <p class="muted">机密客户端密钥以单向哈希保存；轮换时旧密钥只在受控窗口内保留。</p>
      <ul class="session-list"><li v-for="client in clients" :key="client.id"><div><h3>{{ client.name }} <span class="badge">{{ client.kind }}</span> <span class="badge" :class="client.enabled ? 'good' : ''">{{ client.enabled ? '启用' : '已停用' }}</span></h3><p><code>{{ client.clientId }}</code> · 登记于 {{ new Date(client.issuedAt).toLocaleString() }}</p><p class="muted">回调：{{ client.redirectUris.join('、') || '无' }}</p><p class="muted">scope：{{ client.scopes.join(' ') }}</p>
        <p v-if="stateTarget === client.clientId" class="actions"><input v-model="stateReason" :aria-label="(client.enabled ? '停用 ' : '启用 ') + client.clientId + ' 的原因'" placeholder="操作原因" maxlength="500" /><input v-if="client.enabled" v-model="stateConfirm" :aria-label="'输入 ' + client.clientId + ' 以确认停用'" :placeholder="client.clientId" autocomplete="off" spellcheck="false" /><button :class="client.enabled ? 'danger' : ''" :disabled="busy || (client.enabled && stateConfirm !== client.clientId)" @click="toggleState(client)">{{ client.enabled ? '确认停用' : '确认启用' }}</button><button class="secondary" :disabled="busy" @click="stateTarget = ''; stateConfirm = ''">取消</button></p>
        <p v-else-if="deleteTarget === client.clientId" class="actions"><input v-model="deleteReason" :aria-label="'删除 ' + client.clientId + ' 的原因'" placeholder="删除原因" maxlength="500" /><input v-model="deleteConfirm" :aria-label="'输入 ' + client.clientId + ' 以确认删除'" :placeholder="client.clientId" autocomplete="off" spellcheck="false" /><button class="danger" :disabled="busy || deleteConfirm !== client.clientId" @click="remove(client)">确认删除</button><button class="secondary" :disabled="busy" @click="deleteTarget = ''; deleteConfirm = ''; deleteReason = ''">取消</button></p>
        <p v-else-if="rotateTarget === client.clientId" class="actions"><input v-model="rotateReason" :aria-label="'轮换 ' + client.clientId + ' 的原因'" placeholder="轮换原因" maxlength="500" /><button :disabled="busy" @click="rotate">确认轮换</button><button class="secondary" :disabled="busy" @click="rotateTarget = ''">取消</button></p>
        <p v-else class="actions"><button class="secondary" :disabled="busy || client.kind !== 'CONFIDENTIAL'" @click="rotateTarget = client.clientId">轮换密钥</button><button class="secondary" :disabled="busy" @click="beginEdit(client)">编辑</button><button class="secondary" :disabled="busy" @click="stateTarget = client.clientId">{{ client.enabled ? '停用' : '启用' }}</button><button class="danger" :disabled="busy" @click="deleteTarget = client.clientId">删除应用</button></p>
        <form v-if="editTarget === client.clientId" @submit.prevent="saveEdit">
          <p><label :for="'edit-name-' + client.id">显示名称</label><input :id="'edit-name-' + client.id" v-model="editName" maxlength="200" /></p>
          <p><label :for="'edit-redirects-' + client.id">回调地址（每行一个）</label><textarea :id="'edit-redirects-' + client.id" v-model="editRedirects" spellcheck="false"></textarea></p>
          <p><label :for="'edit-logout-' + client.id">退出后重定向（每行一个，可选）</label><textarea :id="'edit-logout-' + client.id" v-model="editLogout" spellcheck="false"></textarea></p>
          <p><label :for="'edit-backchannel-' + client.id">后端退出通知地址（可选）</label><input :id="'edit-backchannel-' + client.id" v-model="editBackchannel" spellcheck="false" /></p>
          <p><label :for="'edit-reason-' + client.id">修改原因</label><textarea :id="'edit-reason-' + client.id" v-model="editReason" maxlength="500"></textarea></p>
          <div class="actions"><button type="submit" :disabled="busy">保存配置</button><button type="button" class="secondary" :disabled="busy" @click="editTarget = ''">取消</button></div>
        </form></div></li></ul>
      <p v-if="busy" role="status">正在处理…</p><p v-else-if="!clients.length && !error">尚未登记应用。</p>
    </section>
    <section class="card"><h2>登记新应用</h2>
      <form @submit.prevent="register">
        <p><label for="client-id">客户端编号</label><input id="client-id" v-model="clientId" autocomplete="off" spellcheck="false" placeholder="crm" /></p>
        <p><label for="client-name">显示名称</label><input id="client-name" v-model="name" autocomplete="off" maxlength="200" /></p>
        <p><label for="client-kind">类型</label><select id="client-kind" v-model="kind"><option value="CONFIDENTIAL">机密客户端（有密钥）</option><option value="NATIVE">原生应用</option><option value="SPA">浏览器 SPA</option></select></p>
        <p><label for="client-redirects">回调地址（每行一个，必须 HTTPS 或已登记的原生 scheme）</label><textarea id="client-redirects" v-model="redirects" autocomplete="off" spellcheck="false"></textarea></p>
        <p><label for="client-logout">退出后重定向（每行一个，可选）</label><textarea id="client-logout" v-model="logoutRedirects" autocomplete="off" spellcheck="false"></textarea></p>
        <p><label for="client-backchannel">后端退出通知地址（固定 /logout/backchannel，可选）</label><input id="client-backchannel" v-model="backchannel" autocomplete="off" spellcheck="false" /></p>
        <p><label for="client-reason">登记原因</label><textarea id="client-reason" v-model="reason" maxlength="500" autocomplete="off"></textarea></p>
        <div class="actions"><button type="submit" :disabled="busy">登记应用</button></div>
      </form>
    </section>
  </template>
</template>
