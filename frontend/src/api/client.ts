/** axios 实例与全局拦截器：统一注入登录令牌、统一错误提示与登录过期跳转。 */
import axios, { AxiosError } from 'axios';
import { message } from 'antd';

/** 登录令牌在 localStorage 中的键名 */
export const TOKEN_STORAGE_KEY = 'siem_token';

/** 读取当前登录令牌（JWT）。 */
export function resolveToken(): string {
  return (localStorage.getItem(TOKEN_STORAGE_KEY) ?? '').trim();
}

/** 保存登录令牌（为空时清除）。 */
export function saveToken(token: string): void {
  if (token && token.trim()) {
    localStorage.setItem(TOKEN_STORAGE_KEY, token.trim());
  } else {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
  }
}

/** 清除登录令牌（退出登录/登录过期时调用）。 */
export function clearToken(): void {
  localStorage.removeItem(TOKEN_STORAGE_KEY);
}

const client = axios.create({
  // 部署时通常与后端同域，默认走 /api/v1；可通过 VITE_API_BASE 覆盖
  baseURL: import.meta.env.VITE_API_BASE || '/api/v1',
  timeout: 30000,
});

// 请求拦截器：自动附加 Bearer 登录令牌
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

/** 判断当前失败请求是否为登录接口本身（登录失败不应触发跳转） */
function isLoginRequest(error: AxiosError): boolean {
  const url = error.config?.url ?? '';
  return url.includes('/auth/login');
}

// 响应拦截器：统一错误提示；登录过期时清除令牌并跳转登录页
client.interceptors.response.use(
  (response) => response,
  (error: AxiosError<{ detail?: unknown }>) => {
    const status = error.response?.status;
    if (status === 401) {
      if (!isLoginRequest(error)) {
        clearToken();
        const now = Date.now();
        if (now - unauthorizedNotifiedAt > 5000 && !window.location.pathname.startsWith('/login')) {
          unauthorizedNotifiedAt = now;
          message.warning('登录已过期，请重新登录');
        }
        // 保留来源路径，登录成功后跳回
        if (!window.location.pathname.startsWith('/login')) {
          const redirect = encodeURIComponent(window.location.pathname + window.location.search);
          window.location.assign(`/login?redirect=${redirect}`);
        }
      }
    } else if (status !== 404 || error.response?.data) {
      message.error(extractDetail(error));
    }
    return Promise.reject(error);
  },
);

export default client;
