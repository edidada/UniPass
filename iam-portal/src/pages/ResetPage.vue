<script setup lang="ts">
import { inject, ref } from 'vue'
import { message, post } from '../api'
import { usePasswordOperation, useWipe } from '../flow'
import OperationPanel from '../components/OperationPanel.vue'
const takeProof = inject<() => string | undefined>('reset-proof', () => undefined)
const proof = ref(takeProof() || ''); const grant = ref(''); const employee = ref(''); const password = ref(''); const confirmation = ref('')
const operation = usePasswordOperation(true); const error = ref(''); const busy = ref(false); const accepted = ref(false); const failedProof = ref(false)
useWipe(proof, grant, password, confirmation)
async function requestLink() {
  if (busy.value) return
  busy.value = true; error.value = ''
  try { await post('/api/password/reset/request', { employee_no: employee.value }); employee.value = ''; accepted.value = true }
  catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
async function verify() {
  if (busy.value || !proof.value) return
  const input = proof.value; proof.value = ''; busy.value = true; error.value = ''
  try { grant.value = (await post<{ reset_token: string }>('/api/password/reset/verify', { token: input })).reset_token }
  catch (failure) { error.value = message(failure); failedProof.value = true } finally { busy.value = false }
}
function reset() {
  if (password.value !== confirmation.value) { error.value = '两次输入的新密码不一致。'; return }
  const input = { reset_token: grant.value, new_password: password.value, confirm_password: confirmation.value }
  password.value = ''; confirmation.value = ''; error.value = ''
  void operation.submit(input).finally(() => { if (operation.phase.value !== 'idle') grant.value = '' })
}
</script>
<template>
  <header class="page-heading"><span class="eyebrow">账户恢复</span><h1>自助重置密码</h1><p>通过企业登记的恢复邮箱确认身份。</p></header>
  <OperationPanel v-if="operation.phase.value !== 'idle'" :phase="operation.phase.value" :result="operation.result.value" :error="operation.error.value" :reset="true" @check="operation.check" />
  <section v-else class="card form-card">
    <p v-if="error || operation.error.value" role="alert" class="error">{{ error || operation.error.value }}</p>
    <template v-if="grant"><h2>设置新密码</h2><p id="reset-policy" class="muted">10–128 个字符，至少三类字符，不得包含个人信息、常见连续字符或历史密码。</p>
      <form @submit.prevent="reset"><label for="reset-password">新密码</label><input id="reset-password" v-model="password" type="password" autocomplete="new-password" required maxlength="1024" aria-describedby="reset-policy"><label for="reset-confirm">确认新密码</label><input id="reset-confirm" v-model="confirmation" type="password" autocomplete="new-password" required maxlength="1024"><button>重置密码</button></form>
    </template>
    <template v-else-if="proof"><h2>恢复链接已载入</h2><p>点击下方按钮验证链接。凭证只在本页内存中使用一次。</p><button :disabled="busy" @click="verify">验证恢复链接</button></template>
    <template v-else-if="busy"><p role="status">正在验证恢复链接…</p></template>
    <template v-else-if="accepted"><h2>申请已受理</h2><p role="status">如果该账户可使用邮件恢复，你将收到后续指引。请检查企业登记的邮箱。</p><a href="/login">返回登录</a></template>
    <template v-else><h2>申请恢复链接</h2><p v-if="failedProof" class="notice">链接可能已使用或过期。请重新申请，勿重复验证旧链接。</p><form @submit.prevent="requestLink"><label for="reset-employee">工号</label><input id="reset-employee" v-model="employee" autocomplete="username" required maxlength="100"><button :disabled="busy">发送恢复指引</button></form></template>
  </section>
</template>
