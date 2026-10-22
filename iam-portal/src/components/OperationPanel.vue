<script setup lang="ts">
import type { PasswordOperation } from '../api'
import { withContinuation } from '../flow'
defineProps<{ phase: string; result?: PasswordOperation; error: string; reset?: boolean }>()
defineEmits<{ check: [] }>()
</script>
<template>
  <section class="card" aria-live="polite" aria-atomic="true">
    <template v-if="result?.state === 'COMMITTED'">
      <span class="badge good">密码已更新</span><h2>请重新登录</h2>
      <p>安全状态已更新，原有登录和令牌已失效。请使用新密码继续。</p>
      <a class="button" :href="withContinuation('/login')">使用新密码登录</a>
    </template>
    <template v-else-if="result?.state === 'REJECTED'">
      <span class="badge">操作未完成</span><h2>目录拒绝了本次修改</h2>
      <p>请检查密码策略，或联系管理员确认目录状态。</p><a class="button secondary" :href="reset ? '/reset' : withContinuation('/portal/password')">开始新的申请</a>
    </template>
    <template v-else>
      <span class="badge">{{ phase === 'submitting' ? '正在提交' : '结果待确认' }}</span><h2>正在确认密码处理结果</h2>
      <p>请勿重新提交密码。此页面只查询原请求，刷新后也可继续查询。</p>
      <p v-if="result?.state === 'UNKNOWN'" class="notice">目录结果尚未确认，需要等待恢复处理；这不表示修改失败。</p>
      <p v-if="error" role="alert" class="error">{{ error }}</p>
      <button v-if="phase === 'paused'" type="button" class="secondary" @click="$emit('check')">重新查询结果</button>
    </template>
    <p v-if="result" class="muted reference">操作编号：{{ result.id }}</p>
  </section>
</template>
