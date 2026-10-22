<script setup lang="ts">
import { ref } from 'vue'
import { message, post } from '../api'
import type { Enrollment, Replacement } from '../api'
import { useAccount, mfaFor, useWipe, withContinuation } from '../flow'
import Reauthenticate from '../components/Reauthenticate.vue'
const { identity, error: accountError, refresh } = useAccount()
const secret = ref(''); const expires = ref(''); const change = ref(''); const code = ref(''); const recovery = ref(''); const busy = ref(false); const error = ref(''); const complete = ref(false)
useWipe(secret, code, recovery, change)
async function begin(mode: 'enroll' | 'rotate' | 'recover') {
  if (busy.value) return
  const input = recovery.value; recovery.value = ''; busy.value = true; error.value = ''
  try {
    const path = mode === 'enroll' ? '/api/mfa/enrollment' : mode === 'rotate' ? '/api/mfa/rotation' : '/api/mfa/recovery'
    const value = await post<Enrollment | Replacement>(path, mode === 'recover' ? { recovery_token: input } : {})
    secret.value = value.secret; expires.value = value.expiresAt; change.value = 'id' in value ? value.id : ''
  } catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
async function confirm() {
  if (busy.value) return
  const input = code.value; code.value = ''; busy.value = true; error.value = ''
  try { await post(change.value ? `/api/mfa/changes/${change.value}/confirm` : '/api/mfa/enrollment/confirm', { code: input }); secret.value = ''; change.value = ''; complete.value = true }
  catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
async function cancel() {
  if (busy.value || !change.value) return
  busy.value = true; error.value = ''
  try { await post(`/api/mfa/changes/${change.value}/cancel`); secret.value = ''; change.value = ''; await refresh() }
  catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
</script>
<template>
  <header class="page-heading"><span class="eyebrow">身份保护</span><h1>管理验证器</h1><p>设置、替换或通过独立授权恢复多因素验证器。</p></header>
  <p v-if="accountError || error" role="alert" class="error">{{ accountError || error }}</p>
  <section v-if="complete" class="card"><span class="badge good">验证器已更新</span><h2>请重新登录并验证</h2><p>旧会话已失效，后续使用新验证器完成验证。</p><a class="button" :href="withContinuation('/login')">重新登录</a></section>
  <template v-else-if="identity">
    <Reauthenticate v-if="!identity.password_recent" @verified="refresh" />
    <section v-else-if="secret" class="card form-card"><h2>在验证器中添加账户</h2><p>选择基于时间的六位验证码，手动输入下方密钥。本页离开后不再显示。</p><p class="secret" aria-label="验证器设置密钥">{{ secret }}</p><p class="muted">有效期至：{{ new Date(expires).toLocaleString() }}</p><form @submit.prevent="confirm"><label for="factor-code">新验证器验证码</label><input id="factor-code" v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required><div class="actions"><button :disabled="busy">确认启用</button><button v-if="change" type="button" class="secondary" :disabled="busy" @click="cancel">取消本次替换</button></div></form></section>
    <section v-else-if="identity.mfa.recovery_required" class="card form-card"><h2>受控恢复验证器</h2><p>请联系管理员完成身份核验并获取恢复授权。输入授权后仅能设置本人的新验证器。</p><form @submit.prevent="begin('recover')"><label for="factor-recovery">恢复授权</label><input id="factor-recovery" v-model="recovery" type="password" autocomplete="off" pattern="[A-Za-z0-9_-]{43}" maxlength="43" required><button :disabled="busy">开始恢复</button></form></section>
    <section v-else-if="!identity.mfa.enrolled" class="card"><h2>设置验证器</h2><p>使用支持 TOTP 的验证器。添加密钥后需要验证一次，才会正式启用。</p><button :disabled="busy" @click="begin('enroll')">开始设置</button></section>
    <section v-else class="card"><h2>替换已启用的验证器</h2><p>替换需要当前密码与原验证器的近期验证。丢失原验证器时，请联系管理员发起受控恢复。</p><a v-if="!identity.mfa.recent" class="button" :href="mfaFor('factors')">验证原验证器</a><button v-else :disabled="busy" @click="begin('rotate')">设置新的验证器</button></section>
  </template>
</template>
