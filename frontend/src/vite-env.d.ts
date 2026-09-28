/// <reference types="vite/client" />

/** 项目使用的 Vite 环境变量类型声明 */
interface ImportMetaEnv {
  /** API 基础前缀，如 /api/v1 */
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
