/// <reference types="vite/client" />

/** 项目使用的 Vite 环境变量类型声明 */
interface ImportMetaEnv {
  /** API 基础前缀，如 /api/v1 */
  readonly VITE_API_BASE?: string;
  /** 默认访问令牌（对应后端 API_TOKEN） */
  readonly VITE_API_TOKEN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
