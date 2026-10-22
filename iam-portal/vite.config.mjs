import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  base: '/portal/',
  build: {
    outDir: process.env.UNIPASS_PORTAL_OUT || 'target/classes/META-INF/resources/portal',
    emptyOutDir: true,
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
    reporters: ['default', 'junit'],
    // Maven keeps the target/ default; the Gradle portalTest task sets UNIPASS_PORTAL_REPORT
    // into its build directory so `gradle clean` removes stale reports together with build/.
    outputFile: process.env.UNIPASS_PORTAL_REPORT || 'target/frontend-test-results.xml',
    clearMocks: true,
  },
})
