/** 应用根组件：登录页为公开路由，其余页面均经过登录守卫并套入整体布局。 */
import { Navigate, Route, Routes } from 'react-router-dom';
import AppLayout from './components/AppLayout';
import RequireAuth from './components/RequireAuth';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import AttackMapPage from './pages/AttackMapPage';
import Alerts from './pages/Alerts';
import Logs from './pages/Logs';
import Rules from './pages/Rules';
import AdminSettings from './pages/AdminSettings';

/** 渲染路由表：/login 公开，其余路由必须登录。 */
export default function App() {
  return (
    <Routes>
      {/* 登录页：无需登录态 */}
      <Route path="/login" element={<Login />} />

      {/* 业务页面：统一经过登录守卫与侧边布局 */}
      <Route
        path="/*"
        element={
          <RequireAuth>
            <AppLayout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/map" element={<AttackMapPage />} />
                <Route path="/alerts" element={<Alerts />} />
                <Route path="/logs" element={<Logs />} />
                <Route path="/rules" element={<Rules />} />
                <Route path="/admin" element={<AdminSettings />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </AppLayout>
          </RequireAuth>
        }
      />
    </Routes>
  );
}
