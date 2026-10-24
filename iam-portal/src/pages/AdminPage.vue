<script setup lang="ts">
import { ref, watch } from 'vue'
import { assertCursor, get, isUuid, message, post } from '../api'
import type { AdminAuditEntry, AdminAuditPage, AuditBatch, AuditVerification } from '../api'
import { useAccount } from '../flow'

const assignable: string[] = ['ROLE_SYSTEM_ADMIN', 'ROLE_ADMIN_APP', 'ROLE_ADMIN_AUDIT', 'ROLE_ADMIN_PASSWORD_RESET', 'ROLE_ADMIN_PASSWORD_RECOVERY', 'ROLE_ADMIN_MFA_RECOVERY']
const { identity, error: accountError } = useAccount()
const hasAudit = () => identity.value?.roles?.some(role => role === 'ROLE_SYSTEM_ADMIN' || role === 'ROLE_ADMIN_AUDIT') ?? false
const hasConsole = () => identity.value?.roles?.includes('ROLE_SYSTEM_ADMIN') ?? false
const audit = ref<AdminAuditEntry[]>([]); const cursor = ref<string | null>(null); const error = ref(''); const busy = ref(false)
const target = ref(''); const roles = ref<string[]>([]); const role = ref<string>(assignable[0]!)
const reason = ref(''); const rolesError = ref(''); const rolesBusy = ref(false); const notice = ref('')

async function loadAudit(more = false) {
  if (busy.value) return
  busy.value = true; error.value = ''
  try {
    if (more) assertCursor(cursor.value)
    const page = await get<AdminAuditPage>('/api/admin/console/audit' + (more && cursor.value ? '?cursor=' + cursor.value : ''))
    audit.value = more ? [...audit.value, ...page.entries] : page.entries; cursor.value = page.nextCursor
  } catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
async function loadRoles(freshTarget = false) {
  if (rolesBusy.value) return
  resetRoleForm(freshTarget)
  if (!isUuid(target.value)) { if (target.value) rolesError.value = '请输入有效的用户编号。'; return }
  rolesBusy.value = true; rolesError.value = ''
  try { roles.value = await get<string[]>(`/api/admin/console/users/${target.value}/roles`) }
  catch (failure) { roles.value = []; rolesError.value = message(failure) } finally { rolesBusy.value = false }
}
function resetRoleForm(freshTarget: boolean): void {
  if (freshTarget) roles.value = []
  notice.value = ''; if (rolesError.value) rolesError.value = ''
}
async function changeKind(action: 'GRANT' | 'REVOKE') {
  if (rolesBusy.value || !isUuid(target.value)) { if (!isUuid(target.value)) rolesError.value = '请输入有效的用户编号。'; return }
  if (!reason.value.trim()) { rolesError.value = '请填写操作原因。'; return }
  rolesBusy.value = true; rolesError.value = ''; notice.value = ''
  try {
    await post(`/api/admin/console/users/${target.value}/roles`,
      { action, role: role.value, reason: reason.value.trim() }, crypto.randomUUID())
    if (action === 'GRANT' && !roles.value.includes(role.value)) roles.value = [...roles.value, role.value].sort()
    if (action === 'REVOKE') roles.value = roles.value.filter(existing => existing !== role.value)
    notice.value = action === 'GRANT' ? '角色已授予，可在审计记录中核对。' : '角色已撤销，可在审计记录中核对。'
    reason.value = ''
  } catch (failure) { rolesError.value = message(failure) } finally { rolesBusy.value = false }
}

const defaultCutoff = new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString().slice(0, 16)
const batches = ref<AuditBatch[]>([]); const cutoff = ref(defaultCutoff); const maxRows = ref(1000)
const archiveError = ref(''); const archiveNotice = ref(''); const archiveBusy = ref(false)

async function loadBatches() {
  if (!hasAudit()) return
  try { batches.value = await get<AuditBatch[]>('/api/admin/console/audit/archive') }
  catch (failure) { archiveError.value = message(failure) }
}
async function archive() {
  if (archiveBusy.value || !hasConsole()) return
  archiveBusy.value = true; archiveError.value = ''; archiveNotice.value = ''
  try {
    const batch = await post<AuditBatch>('/api/admin/console/audit/archive', {
      cutoff: new Date(cutoff.value).toISOString(), max_rows: maxRows.value,
    })
    archiveNotice.value = batch ? `已归档 ${batch.rows} 条，批次 ${batch.id}。` : '没有早于截止时间的记录。'
    await Promise.all([loadBatches(), loadAudit()])
  } catch (failure) { archiveError.value = message(failure) } finally { archiveBusy.value = false }
}
async function verifyBatch(batch: AuditBatch) {
  archiveBusy.value = true; archiveError.value = ''; archiveNotice.value = ''
  try {
    const result = await get<AuditVerification>(`/api/admin/console/audit/archive/${batch.id}`)
    archiveNotice.value = result.intact ? '完整性校验通过。' : '完整性校验失败，批次可能被篡改。'
  } catch (failure) { archiveError.value = message(failure) } finally { archiveBusy.value = false }
}
async function restoreBatch(batch: AuditBatch) {
  if (!hasConsole()) return
  archiveBusy.value = true; archiveError.value = ''; archiveNotice.value = ''
  try {
    const result = await post<{ restored: number }>(`/api/admin/console/audit/archive/${batch.id}/restore`)
    archiveNotice.value = `已恢复 ${result.restored} 条记录。`
    await Promise.all([loadBatches(), loadAudit()])
  } catch (failure) { archiveError.value = message(failure) } finally { archiveBusy.value = false }
}

watch(identity, value => { if (value) {
  if (hasAudit()) { void loadAudit(); void loadBatches() } else error.value = '此账户没有管理控制台权限。'
} })
function inRoles(roleValue: string): boolean { return roles.value.includes(roleValue) }
function detailText(entry: AdminAuditEntry): string {
  const parts: string[] = []
  if (entry.detail.role) parts.push('角色 ' + entry.detail.role)
  if (entry.detail.reason) parts.push('原因 ' + entry.detail.reason)
  if (entry.detail.replay) parts.push('重放 ' + entry.detail.replay)
  return parts.join(' · ')
}
</script>
<template>
  <header class="page-heading"><span class="eyebrow">管理控制台</span><h1>审计与角色</h1><p>查询控制台审计记录，授予或撤销管理角色。所有写操作都会留痕。</p></header>
  <p v-if="accountError || error" role="alert" class="error">{{ accountError || error }}</p>
  <template v-if="identity && hasAudit()">
    <section class="card"><h2>审计记录</h2><p class="muted">最新优先，每次最多 100 条；导出的 CSV 仅限 1000 行。</p>
      <ul class="session-list"><li v-for="entry in audit" :key="entry.id"><div><h3>{{ entry.action }} <span class="badge" :class="entry.result === 'SUCCESS' ? 'good' : ''">{{ entry.result }}</span></h3><p>{{ new Date(entry.createdAt).toLocaleString() }}<template v-if="entry.subject"> · 对象 {{ entry.subject }}</template></p><p class="muted" v-if="detailText(entry)">{{ detailText(entry) }}</p></div></li></ul>
      <p v-if="busy" role="status">正在加载…</p><p v-else-if="!audit.length && !error">暂无审计记录。</p><button v-if="cursor" class="secondary" :disabled="busy" @click="loadAudit(true)">加载更多记录</button>
    </section>
    <section class="card"><h2>审计归档</h2><p class="muted">早于截止时间的记录会移入归档表并生成 SHA-256 批次摘要；恢复前校验完整性，重复恢复不会重复插入。</p>
      <form v-if="hasConsole()" @submit.prevent="archive">
        <p><label for="archive-cutoff">截止时间（UTC）</label><input id="archive-cutoff" v-model="cutoff" type="datetime-local" /></p>
        <p><label for="archive-max">每批上限</label><input id="archive-max" v-model.number="maxRows" type="number" min="1" max="10000" /></p>
        <div class="actions"><button type="submit" :disabled="archiveBusy">归档此前的记录</button></div>
      </form>
      <ul class="session-list"><li v-for="batch in batches" :key="batch.id"><div><h3>批次 {{ batch.id.slice(0, 8) }} <span class="badge">{{ batch.rows }} 条</span></h3><p>截止 {{ new Date(batch.cutoff).toLocaleString() }} · 归档于 {{ new Date(batch.createdAt).toLocaleString() }}</p><p class="muted reference">{{ batch.digest }}</p></div>
        <p class="actions"><button class="secondary" :disabled="archiveBusy" @click="verifyBatch(batch)">校验</button><button v-if="hasConsole()" class="secondary" :disabled="archiveBusy" @click="restoreBatch(batch)">恢复</button></p></li></ul>
      <p v-if="archiveBusy" role="status">正在处理…</p><p v-else-if="!batches.length">暂无归档批次。</p>
      <p v-if="archiveError" role="alert" class="error">{{ archiveError }}</p><p v-if="archiveNotice" role="status" class="good">{{ archiveNotice }}</p>
    </section>
    <section v-if="hasConsole()" class="card"><h2>管理角色</h2><p class="muted">仅允许操作员人不可推导的固定角色集合；同一幂等键重放同一上下文会被拒绝。</p>
      <form @submit.prevent="changeKind('GRANT')">
        <p><label for="admin-target">用户编号（UUID）</label><input id="admin-target" v-model="target" autocomplete="off" spellcheck="false" placeholder="00000000-0000-0000-0000-000000000000" @blur="loadRoles(true)" /></p>
        <p v-if="roles.length">现有角色：{{ roles.join('、') }}</p><p v-else-if="target && !rolesBusy && isUuid(target)">该对象暂无可显示角色。</p>
        <p><label for="admin-role">角色</label><select id="admin-role" v-model="role"><option v-for="option in assignable" :key="option" :value="option">{{ option }}</option></select></p>
        <p><label for="admin-reason">操作原因</label><textarea id="admin-reason" v-model="reason" required maxlength="500" autocomplete="off"></textarea></p>
        <div class="actions"><button type="button" class="secondary" :disabled="rolesBusy || !inRoles(role)" @click="changeKind('REVOKE')">撤销角色</button><button type="submit" :disabled="rolesBusy || inRoles(role)">授予角色</button></div>
      </form>
      <p v-if="rolesBusy" role="status">正在处理…</p>
      <p v-if="rolesError" role="alert" class="error">{{ rolesError }}</p>
      <p v-if="notice" role="status" class="good">{{ notice }}</p>
    </section>
  </template>
</template>
