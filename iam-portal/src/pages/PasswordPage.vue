<script setup lang="ts">
import { ref } from 'vue'
import { useAccount, usePasswordOperation, useWipe, mfaFor } from '../flow'
import OperationPanel from '../components/OperationPanel.vue'
import Reauthenticate from '../components/Reauthenticate.vue'
const operation = usePasswordOperation(false); const { identity, error, loading, refresh } = useAccount(!operation.resuming)
const current = ref(''); const password = ref(''); const confirmation = ref(''); const validation = ref(''); useWipe(current, password, confirmation)
function submit() {
  if (password.value !== confirmation.value) { validation.value = '两次输入的新密码不一致。'; return }
  const input = { old_password: current.value, new_password: password.value, confirm_password: confirmation.value }
  current.value = ''; password.value = ''; confirmation.value = ''; validation.value = ''; void operation.submit(input)
}
</script>
<template>
  <header class="page-heading"><span class="eyebrow">密码管理</span><h1>修改账户密码</h1><p>修改成功后，原有登录和令牌将失效。</p></header>
  <OperationPanel v-if="operation.phase.value !== 'idle'" :phase="operation.phase.value" :result="operation.result.value" :error="operation.error.value" @check="operation.check" />
  <template v-else>
    <p v-if="loading" role="status">正在读取账户信息…</p><p v-if="error" role="alert" class="error">{{ error }}</p>
    <template v-if="identity">
      <section v-if="identity.mfa.required && !identity.mfa.recent" class="notice"><h2>请先完成多因素验证</h2><a class="button" :href="mfaFor('password')">验证身份</a></section>
      <Reauthenticate v-else-if="!identity.password_recent" @verified="refresh" />
      <section v-else class="card form-card"><h2>{{ identity.must_change_password ? '设置新的安全密码' : '更新密码' }}</h2><p id="password-policy" class="muted">10–128 个字符，至少包含大写、小写、数字、符号中的三类；不能包含工号、姓名或常见连续字符。目录还会校验历史密码。</p>
        <form @submit.prevent="submit"><label for="old-password">当前密码</label><input id="old-password" v-model="current" type="password" autocomplete="current-password" required maxlength="1024">
          <label for="new-password">新密码</label><input id="new-password" v-model="password" type="password" autocomplete="new-password" required maxlength="1024" aria-describedby="password-policy">
          <label for="confirm-password">确认新密码</label><input id="confirm-password" v-model="confirmation" type="password" autocomplete="new-password" required maxlength="1024">
          <p v-if="validation || operation.error.value" role="alert" class="error">{{ validation || operation.error.value }}</p><button>更新密码</button>
        </form>
      </section>
    </template>
  </template>
</template>
