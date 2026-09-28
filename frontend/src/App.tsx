/** 应用根组件：定义侧边布局与各功能页面路由。 */
import { Navigate, Route, Routes } from 'react-router-dom';
import AppLayout from './components/AppLayout';
import Dashboard from './pages/Dashboard';
import AttackMapPage from './pages/AttackMapPage';
import Alerts from './pages/Alerts';
import Logs from './pages/Logs';
import Rules from './pages/Rules';

/** 渲染整体布局与路由表。 */
export default function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/map" element={<AttackMapPage />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/logs" element={<Logs />} />
        <Route path="/rules" element={<Rules />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppLayout>
  );
}
