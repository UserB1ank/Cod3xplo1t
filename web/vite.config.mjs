import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 5173,
    proxy: {
      '/api': { target: process.env.CODEXPLOIT_API_URL || 'http://127.0.0.1:8080', changeOrigin: false },
    },
  },
  build: { sourcemap: false },
});
