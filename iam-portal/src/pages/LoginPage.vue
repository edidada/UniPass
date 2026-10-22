<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { csrf, message, post } from '../api'
import type { Csrf } from '../api'
const proof = ref<Csrf>(); const error = ref(''); const busy = ref(false)
const query = new URLSearchParams(window.location.search)
const passwordInput = ref<HTMLInputElement>()
const clear = () => { if (passwordInput.value) passwordInput.value.value = '' }
onMounted(() => window.addEventListener('pagehide', clear))
onBeforeUnmount(() => { clear(); window.removeEventListener('pagehide', clear) })
onMounted(async () => { try { proof.value = await csrf() } catch (failure) { error.value = message(failure) } })
async function external() {
  if (busy.value) return
  busy.value = true; error.value = ''
  try {
    const result = await post<{ authorizationUrl: string }>('/api/connector/feishu/login/start')
    const url = new URL(result.authorizationUrl)
    if (url.protocol !== 'https:' || url.hostname !== 'accounts.feishu.cn' || url.pathname !== '/open-apis/authen/v1/authorize') throw new Error()
    window.location.assign(url.href)
  } catch (failure) { error.value = message(failure); busy.value = false }
}
</script>
<template>
  <div class="auth-intro"><span class="eyebrow">统一身份 · 安全访问</span><h1>登录 UniPass</h1><p>一个企业身份，连接日常工作。</p></div>
  <section class="card login-card">
    <h2>使用企业账户</h2>
    <p v-if="query.has('error')" role="alert" class="error">账户或密码验证失败，请重新输入。</p>
    <p v-if="query.has('external_error')" role="alert" class="error">外部登录未完成，请重新发起登录。</p>
    <p v-if="query.has('logout')" role="status" class="notice">你已退出登录。</p>
    <p v-if="error" role="alert" class="error">{{ error }}</p>
    <form method="post" action="/login">
      <input v-if="proof" type="hidden" :name="proof.parameter_name" :value="proof.token">
      <label for="username">工号</label><input id="username" name="username" autocomplete="username" required maxlength="100" autofocus>
      <label for="password">密码</label><input id="password" ref="passwordInput" name="password" type="password" autocomplete="current-password" required maxlength="1024">
      <button class="wide" :disabled="!proof">登录</button>
    </form>
    <div class="form-links"><a href="/reset">忘记密码</a><button type="button" class="text-button" :disabled="busy || !proof" @click="external">使用飞书登录</button></div>
  </section>
  <p class="security-note">请在本人设备完成验证，勿向他人提供密码或验证码。</p>
</template>
