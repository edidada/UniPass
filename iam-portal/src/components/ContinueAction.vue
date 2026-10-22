<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { csrf, message } from '../api'
import type { Csrf } from '../api'
import { continuation } from '../flow'
const id = continuation(); const proof = ref<Csrf>(); const error = ref('')
const props = defineProps<{ task?: 'password' | 'sessions' | 'factors' | 'binding' }>()
onMounted(async () => { if (id) { try { proof.value = await csrf() } catch (failure) { error.value = message(failure) } } })
</script>
<template>
  <p v-if="error" role="alert" class="error">{{ error }}</p>
  <form v-if="id && proof" method="post" action="/portal/continue">
    <input type="hidden" name="id" :value="id">
    <input type="hidden" :name="proof.parameter_name" :value="proof.token">
    <button type="submit">继续访问应用</button>
  </form>
  <a v-else-if="!id" class="button" :href="props.task ? '/portal/' + props.task : '/portal/'">{{ props.task ? '继续原操作' : '返回账户概览' }}</a>
</template>
