/** axios 实例与全局拦截器：统一注入访问令牌、统一错误提示。 */
import axios, { AxiosError } from 'axios';
import { message } from 'antd';
import type { Alert, PageResult } from './types';

/** 访问令牌在 localStorage 中的键名 */
export const TOKEN_STORAGE_KEY = 'siem_token';

/**
 * 读取当前生效的访问令牌。
 * 优先使用用户在页面中保存的令牌，其次回退到构建期环境变量 VITE_API_TOKEN。
 */
export function resolveToken(): string {
  const stored = localStorage.getItem(TOKEN_STORAGE_KEY);
  if (stored && stored.trim()) {
    return stored.trim();
  }
  const envToken = import.meta.env.VITE_API_TOKEN;
  return envToken && envToken.trim() ? envToken.trim() : '';
}

/** 保存或清除访问令牌（为空时清除），供页面上的令牌设置入口调用。 */
export function saveToken(token: string): void {
  if (token && token.trim()) {
    localStorage.setItem(TOKEN_STORAGE_KEY, token.trim());
  } else {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
  }
}

/** 获取当前令牌的展示值，用于填充设置框（仅本地使用，不回传服务端）。 */
export function loadStoredToken(): string {
  return localStorage.getItem(TOKEN_STORAGE_KEY) ?? '';
}

const client = axios.create({
  // 部署时通常与后端同域，默认走 /api/v1；可通过 VITE_API_BASE 覆盖
  baseURL: import.meta.env.VITE_API_BASE || '/api/v1',
  timeout: 30000,
});

// 请求拦截器：自动附加 Bearer 令牌
client.interceptors.request.use((config) => {
  const token = resolveToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// 401 提示做去抖，避免自动刷新时反复弹窗
let unauthorizedNotifiedAt = 0;

/** 从错误对象中提取后端返回的 detail 文本 */
function extractDetail(error: AxiosError<{ detail?: unknown }>): string {
  const detail = error.response?.data?.detail;
  if (typeof detail === 'string' && detail) {
    return detail;
  }
  return error.message || '请求失败';
}

// 响应拦截器：统一错误提示
client.interceptors.response.use(
  (response) => response,
  (error: AxiosError<{ detail?: unknown }>) => {
    const status = error.response?.status;
    if (status === 401) {
      const now = Date.now();
      if (now - unauthorizedNotifiedAt > 5000) {
        unauthorizedNotifiedAt = now;
        message.error('访问令牌无效或已过期，请在右上角重新设置 API Token');
      }
    } else if (status !== 404 || error.response?.data) {
      message.error(extractDetail(error));
    }
    return Promise.reject(error);
  },
);

/** 类型导出，方便其它模块引用 */
export type { Alert, PageResult };

export default client;
