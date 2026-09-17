import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// jess-web Vite config — Phase 5e-2.
//
// Build target: `dist/` is embedded by the Go binary (see cmd/jess-web/main.go
// `//go:embed all:web/dist`). Vite outputs a hashed, fingerprinted bundle so
// the Go server can serve assets with long-lived Cache-Control and the
// app shell with no-cache.
//
// Dev: `pnpm dev` runs Vite on :5173 with a proxy for /auth, /api, /ws so the
// React app can talk to a locally-running jess-web Go server on :7102.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
    // Cap chunk warnings: xterm + react split keeps initial transfer well
    // under any meaningful threshold; flag anything unusual.
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks: {
          xterm: ['@xterm/xterm', '@xterm/addon-fit'],
          react: ['react', 'react-dom', 'react-router-dom'],
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/auth': 'http://localhost:7102',
      '/api': 'http://localhost:7102',
      '/ws': {
        target: 'ws://localhost:7102',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  preview: {
    port: 4173,
  },
})
