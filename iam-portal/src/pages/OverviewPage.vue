<script setup lang="ts">
import { useAccount, withContinuation } from '../flow'
const { identity, error, loading } = useAccount()
</script>
<template>
  <header class="page-heading"><span class="eyebrow">账户中心</span><h1>账户安全概览</h1><p>管理验证方式、密码与已登录的设备。</p></header>
  <p v-if="loading" role="status">正在读取账户信息…</p><p v-if="error" role="alert" class="error">{{ error }}</p>
  <template v-if="identity">
    <section v-if="identity.must_change_password" class="notice"><strong>需要更新密码</strong><p>完成必要的多因素验证后，设置新密码以继续访问应用。</p><a :href="withContinuation('/portal/password')">前往修改密码</a></section>
    <section v-if="identity.mfa.recovery_required" class="notice"><strong>需要恢复验证器</strong><p>请凭管理员独立签发的恢复授权重新设置验证器。</p><a :href="withContinuation('/portal/factors')">恢复验证器</a></section>
    <div class="card-grid">
      <section class="card"><span class="card-label">当前身份</span><h2>{{ identity.method === 'FEISHU' ? '飞书登录' : '密码登录' }}</h2><p class="reference">{{ identity.sub }}</p><p class="muted">登录时间：{{ new Date(identity.authenticated_at).toLocaleString() }}</p></section>
      <section class="card"><span class="card-label">多因素验证</span><h2>{{ identity.mfa.enrolled ? '验证器已启用' : '尚未设置验证器' }}</h2><p>{{ identity.mfa.recent ? '已完成近期验证。' : '敏感操作可能需要再次验证。' }}</p><a :href="withContinuation(identity.mfa.enrolled ? '/portal/mfa' : '/portal/factors')">{{ identity.mfa.enrolled ? '验证身份' : '设置验证器' }}</a></section>
      <section class="card"><span class="card-label">登录记录</span><h2>查看与撤销登录</h2><p>识别不熟悉的登录，撤销对应应用访问权限。</p><a href="/portal/sessions">管理登录</a></section>
      <section class="card"><span class="card-label">密码</span><h2>更新账户密码</h2><p>修改后需要在各端重新登录。</p><a :href="withContinuation('/portal/password')">修改密码</a></section>
    </div>
  </template>
</template>
