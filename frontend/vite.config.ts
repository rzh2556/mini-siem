/** Vite 构建配置：开发环境代理到本地 FastAPI 后端，生产构建输出到 dist。 */
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // 开发时把 /api 请求转发到本地后端，避免跨域问题
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    // ECharts / Leaflet 体积较大，放宽单文件体积告警阈值
    chunkSizeWarningLimit: 2000,
    // 把体积较大的三方库拆分为独立 chunk，避免首屏加载单个超大文件
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          antd: ['antd', '@ant-design/icons'],
          charts: ['echarts', 'echarts-for-react'],
          map: ['leaflet', 'react-leaflet'],
        },
      },
    },
  },
});
