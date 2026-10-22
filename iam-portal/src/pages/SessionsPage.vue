<script setup lang="ts">
import { ref, watch } from 'vue'
import { get, message, post } from '../api'
import type { LoginEntry, LoginPage } from '../api'
import { useAccount, mfaFor, withContinuation } from '../flow'
import Reauthenticate from '../components/Reauthenticate.vue'
const { identity, error: accountError, refresh } = useAccount()
const entries = ref<LoginEntry[]>([]); const cursor = ref<string | null>(null); const error = ref(''); const busy = ref(false); const target = ref<LoginEntry>()
async function load(more = false) {
  if (busy.value) return
  busy.value = true; error.value = ''
  try { const page = await get<LoginPage>('/api/session/logins' + (more && cursor.value ? '?before=' + cursor.value : '')); entries.value = more ? [...entries.value, ...page.entries] : page.entries; cursor.value = page.nextCursor }
  catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
watch(identity, value => { if (value) void load() })
async function revoke() {
  if (busy.value || !target.value) return
  const selected = target.value; busy.value = true; error.value = ''
  try { await post(`/api/session/logins/${selected.id}/revoke`); target.value = undefined; if (selected.current) { window.location.assign(withContinuation('/login')); return }; entries.value = entries.value.filter(entry => entry.id !== selected.id) }
  catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
</script>
<template>
  <header class="page-heading"><span class="eyebrow">访问管理</span><h1>已登录的账户</h1><p>撤销一次登录及其关联的应用访问，其他登录保持有效。</p></header>
  <p v-if="accountError || error" role="alert" class="error">{{ accountError || error }}</p>
  <template v-if="identity">
    <section v-if="identity.mfa.required && !identity.mfa.recent" class="notice"><p>撤销登录前，请先验证身份。</p><a class="button" :href="mfaFor('sessions')">多因素验证</a></section>
    <Reauthenticate v-else-if="!identity.password_recent" @verified="refresh" />
    <section v-if="target" class="card confirmation" role="region" aria-labelledby="revoke-title"><h2 id="revoke-title">{{ target.current ? '撤销当前登录？' : '撤销这次登录？' }}</h2><p>{{ target.device }} · {{ new Date(target.authenticatedAt).toLocaleString() }}</p><p>关联应用的令牌会失效，后续使用需要重新登录。</p><div class="actions"><button class="danger" :disabled="busy" @click="revoke">确认撤销</button><button class="secondary" :disabled="busy" @click="target = undefined">取消</button></div></section>
    <section class="card"><h2>登录记录</h2><p class="muted">设备信息仅供参考，可被伪造。浏览器会话过期后，仍有效的应用授权也可在此撤销。最近活动为采样记录。</p>
      <ul class="session-list"><li v-for="entry in entries" :key="entry.id"><div><h3>{{ entry.device }} <span v-if="entry.current" class="badge good">当前登录</span></h3><p>{{ entry.method === 'FEISHU' ? '飞书' : '密码' }} · {{ new Date(entry.authenticatedAt).toLocaleString() }}</p><p class="muted">最近活动：{{ new Date(entry.lastAccessAt).toLocaleString() }}</p></div><button class="secondary" :disabled="busy || !identity.password_recent || (identity.mfa.required && !identity.mfa.recent)" :aria-label="'撤销 ' + entry.device + (entry.current ? ' 当前登录' : '')" @click="target = entry">撤销登录</button></li></ul>
      <p v-if="busy" role="status">正在处理…</p><p v-else-if="!entries.length">没有可显示的登录。</p><button v-if="cursor" class="secondary" :disabled="busy" @click="load(true)">加载更多登录</button>
    </section>
  </template>
</template>
