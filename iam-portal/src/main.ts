import { createApp } from 'vue'
import App from './App.vue'
import { takeFragmentProof } from './flow'
import './style.css'

// Strip the email credential before the first application request or render.
const takeProof = takeFragmentProof(window.location, window.history)
window.addEventListener('pagehide', () => { takeProof() })
window.addEventListener('pageshow', event => { if (event.persisted) window.location.reload() })
createApp(App).provide('reset-proof', takeProof).mount('#app')
