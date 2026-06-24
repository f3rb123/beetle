import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Single-bundle SPA: ~735 kB minified / ~210 kB gzip is well within budget for
  // an offline workstation tool, so the 500 kB advisory is raised rather than
  // forcing speculative code-splitting at the release freeze.
  build: {
    chunkSizeWarningLimit: 1000,
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:9005',
        changeOrigin: true,
      }
    }
  }
})
