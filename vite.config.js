import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
  },
  build: {
    rollupOptions: {
      input: {
        main: './index.html',
        scanner: './scanner.html',
        analysisResults: './analysis-results.html'
      }
    }
  }
})
