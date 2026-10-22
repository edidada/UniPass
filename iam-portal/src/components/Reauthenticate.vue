<script setup lang="ts">
import { ref } from 'vue'
import { message, post } from '../api'
import { useWipe } from '../flow'
const emit = defineEmits<{ verified: [] }>()
const password = ref(''); const busy = ref(false); const error = ref(''); useWipe(password)
async function verify() {
  if (busy.value) return
  const input = password.value; password.value = ''; busy.value = true; error.value = ''
  try { await post('/api/session/reauthenticate', { password: input }); emit('verified') }
  catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
</script>
<template>
  <section class="card">
    <h2>确认当前密码</h2><p>此操作需要近期的目录密码验证。飞书登录和验证码验证不代替此步骤。</p>
    <form @submit.prevent="verify">
      <label for="reauth-password">当前密码</label><input id="reauth-password" v-model="password" type="password" autocomplete="current-password" required maxlength="1024">
      <p v-if="error" role="alert" class="error">{{ error }}</p>
      <button :disabled="busy">{{ busy ? '验证中…' : '验证当前密码' }}</button>
    </form>
  </section>
</template>
