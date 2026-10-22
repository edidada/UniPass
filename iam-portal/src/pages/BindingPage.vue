<script setup lang="ts">
import { ref } from 'vue'
import { message, post } from '../api'
import { useAccount, mfaFor, withContinuation } from '../flow'
import Reauthenticate from '../components/Reauthenticate.vue'
const { identity, error: accountError, refresh } = useAccount(); const error = ref(''); const busy = ref(false); const removing = ref(false)
const bound = new URLSearchParams(window.location.search).has('bound')
async function bind() {
  if (busy.value) return
  busy.value = true; error.value = ''
  try {
    const value = await post<{ authorizationUrl: string }>('/api/connector/feishu/binding/start'); const url = new URL(value.authorizationUrl)
    if (url.protocol !== 'https:' || url.hostname !== 'accounts.feishu.cn' || url.pathname !== '/open-apis/authen/v1/authorize') throw new Error()
    window.location.assign(url.href)
  } catch (failure) { error.value = message(failure); busy.value = false }
}
async function remove() {
  if (busy.value) return
  busy.value = true; error.value = ''
  try { await post('/api/connector/feishu/binding/remove'); window.location.assign(withContinuation('/login')) }
  catch (failure) { error.value = message(failure); busy.value = false }
}
</script>
<template>
  <header class="page-heading"><span class="eyebrow">登录方式</span><h1>飞书身份绑定</h1><p>将经过核验的本人企业身份用于快捷登录。</p></header>
  <p v-if="bound" role="status" class="notice">绑定操作已完成。密码更新后需要重新确认绑定。</p><p v-if="accountError || error" role="alert" class="error">{{ accountError || error }}</p>
  <template v-if="identity">
    <Reauthenticate v-if="!identity.password_recent" @verified="refresh" />
    <section v-else-if="identity.mfa.required && !identity.mfa.recent" class="notice"><p>请先完成多因素验证。</p><a class="button" :href="mfaFor('binding')">验证身份</a></section>
    <section v-else-if="identity.must_change_password || identity.mfa.recovery_required" class="notice"><p>请先完成密码更新或验证器恢复，再管理绑定。</p><a :href="withContinuation(identity.mfa.recovery_required ? '/portal/factors' : '/portal/password')">处理账户状态</a></section>
    <section v-else class="card"><h2>确认本人飞书身份</h2><p>绑定只接受系统固定企业和应用中的身份。该功能须由管理员完成平台核验后开放。</p><div class="actions"><button :disabled="busy" @click="bind">绑定或续绑本人身份</button><button class="secondary" :disabled="busy" @click="removing = true">解除本人绑定</button></div><div v-if="removing" class="notice"><h3>确认解除绑定？</h3><p>解除后当前登录将失效，需要重新验证身份。</p><div class="actions"><button class="danger" :disabled="busy" @click="remove">确认解除</button><button class="secondary" :disabled="busy" @click="removing = false">取消</button></div></div></section>
  </template>
</template>
