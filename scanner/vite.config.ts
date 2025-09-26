import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  root: 'scanner',
  publicDir: 'scanner/public',
  server: {
    host: 'localhost',
    port: 5173,
    strictPort: true
  },
  plugins: [react()]
})
