<script setup lang="ts">
import { ref } from 'vue'
import { message, post } from '../api'
import { useAccount, useWipe, withContinuation } from '../flow'
import ContinueAction from '../components/ContinueAction.vue'
const { identity, error: accountError, loading, refresh } = useAccount()
const code = ref(''); const busy = ref(false); const error = ref(''); const verified = ref(false); useWipe(code)
const taskValue = new URLSearchParams(window.location.search).get('task')
const task = taskValue && ['password', 'sessions', 'factors', 'binding'].includes(taskValue) ? taskValue as 'password' | 'sessions' | 'factors' | 'binding' : undefined
async function verify() {
  if (busy.value) return
  const input = code.value; code.value = ''; busy.value = true; error.value = ''
  try {
    const context = await post<{ context: string }>('/api/mfa/context')
    const challenge = await post<{ challenge: string }>('/api/mfa/challenges', context)
    await post('/api/mfa/verify', { ...context, ...challenge, code: input }); verified.value = true; await refresh()
  } catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
</script>
<template>
  <header class="page-heading"><span class="eyebrow">身份验证</span><h1>多因素验证</h1><p>输入验证器当前显示的六位验证码。</p></header>
  <p v-if="loading" role="status">正在读取验证状态…</p><p v-if="accountError" role="alert" class="error">{{ accountError }}</p>
  <section v-if="identity" class="card form-card">
    <template v-if="verified || identity.mfa.recent"><span class="badge good">验证已完成</span><h2>身份已确认</h2><p>验证有时间限制，请继续原操作。</p><ContinueAction :task="task" /></template>
    <template v-else-if="!identity.mfa.enrolled || identity.mfa.recovery_required"><h2>需要设置或恢复验证器</h2><p>当前没有可用的验证器。恢复操作需要管理员签发的授权。</p><a class="button" :href="withContinuation('/portal/factors')">管理验证器</a></template>
    <form v-else @submit.prevent="verify"><label for="otp">验证码</label><input id="otp" v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required :disabled="busy" aria-describedby="otp-help"><p id="otp-help" class="muted">请使用新验证码，不要与他人分享。</p><p v-if="error" role="alert" class="error">{{ error }}</p><button :disabled="busy">{{ busy ? '验证中…' : '验证身份' }}</button></form>
  </section>
</template>
