/** 登录路由守卫：无令牌或令牌失效时重定向到登录页，登录后回到原页面。 */
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Spin } from 'antd';
import { fetchMe } from '../api/endpoints';
import { resolveToken } from '../api/client';

interface RequireAuthProps {
  children: ReactNode;
}

/** 校验本地登录态，通过后渲染受保护内容。 */
export default function RequireAuth({ children }: RequireAuthProps) {
  const location = useLocation();
  const [status, setStatus] = useState<'checking' | 'ok' | 'fail'>('checking');

  useEffect(() => {
    if (!resolveToken()) {
      setStatus('fail');
      return;
    }
    let cancelled = false;
    fetchMe()
      .then(() => {
        if (!cancelled) {
          setStatus('ok');
        }
      })
      .catch(() => {
        // 401 拦截器会处理跳转，这里仅停止渲染受保护内容
        if (!cancelled) {
          setStatus('fail');
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (status === 'checking') {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <Spin size="large" tip="正在校验登录状态…" />
      </div>
    );
  }
  if (status === 'fail') {
    const redirect = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?redirect=${redirect}`} replace />;
  }
  return <>{children}</>;
}
