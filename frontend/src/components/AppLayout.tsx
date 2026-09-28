/** 应用整体布局：左侧导航栏（平台名称 + 后端健康状态 + 当前用户）与右侧内容区。 */
import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  Badge,
  Dropdown,
  Layout,
  Menu,
  Space,
  Tooltip,
  Typography,
} from 'antd';
import {
  AlertOutlined,
  DashboardOutlined,
  FileSearchOutlined,
  GlobalOutlined,
  KeyOutlined,
  LogoutOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  SlidersOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { fetchHealth, fetchMe } from '../api/endpoints';
import { clearToken } from '../api/client';
import ChangePasswordModal from './ChangePasswordModal';
import type { HealthResponse } from '../api/types';

/** 侧边导航菜单项 */
const MENU_ITEMS = [
  { key: '/', icon: <DashboardOutlined />, label: <Link to="/">仪表盘</Link> },
  { key: '/map', icon: <GlobalOutlined />, label: <Link to="/map">攻击地图</Link> },
  { key: '/alerts', icon: <AlertOutlined />, label: <Link to="/alerts">告警中心</Link> },
  { key: '/logs', icon: <FileSearchOutlined />, label: <Link to="/logs">日志检索</Link> },
  { key: '/rules', icon: <SlidersOutlined />, label: <Link to="/rules">规则管理</Link> },
  { key: '/admin', icon: <SettingOutlined />, label: <Link to="/admin">系统设置</Link> },
];

/** 布局属性 */
interface AppLayoutProps {
  /** 右侧内容区 */
  children: ReactNode;
}

/** 渲染应用框架：左侧固定导航 + 顶部标题健康状态 + 内容区。 */
export default function AppLayout({ children }: AppLayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthFailed, setHealthFailed] = useState(false);
  const [username, setUsername] = useState('');
  const [passwordOpen, setPasswordOpen] = useState(false);

  /** 拉取后端健康状态与当前登录用户 */
  const loadHealth = useCallback(() => {
    fetchHealth()
      .then((data) => {
        setHealth(data);
        setHealthFailed(false);
      })
      .catch(() => {
        setHealth(null);
        setHealthFailed(true);
      });
    fetchMe()
      .then((user) => setUsername(user.username))
      .catch(() => undefined);
  }, []);

  // 每 30 秒轮询一次健康状态，组件卸载时清除定时器
  useEffect(() => {
    loadHealth();
    const timer = window.setInterval(loadHealth, 30000);
    return () => window.clearInterval(timer);
  }, [loadHealth]);

  /** 计算健康状态指示灯的颜色与文案 */
  const healthBadge = () => {
    if (healthFailed) {
      return { status: 'error' as const, text: '后端不可达' };
    }
    if (!health) {
      return { status: 'processing' as const, text: '检测中' };
    }
    if (health.status === 'ok') {
      return { status: 'success' as const, text: '服务正常' };
    }
    return { status: 'warning' as const, text: '服务降级（存储未连接）' };
  };

  const badge = healthBadge();

  /** 退出登录：清除本地令牌并回到登录页 */
  const handleLogout = () => {
    clearToken();
    navigate('/login', { replace: true });
  };

  /** 用户下拉菜单 */
  const userMenu = {
    items: [
      { key: 'password', icon: <KeyOutlined />, label: '修改密码' },
      { type: 'divider' as const },
      { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', danger: true },
    ],
    onClick: ({ key }: { key: string }) => {
      if (key === 'password') {
        setPasswordOpen(true);
      } else if (key === 'logout') {
        handleLogout();
      }
    },
  };

  /** 选中菜单项 */
  const selectedKey = MENU_ITEMS.some((item) => item.key === location.pathname)
    ? location.pathname
    : '/';

  return (
    <Layout className="app-layout">
      <Layout.Sider width={228} className="app-sider" theme="dark">
        <div className="app-brand">
          <SafetyCertificateOutlined className="app-brand__icon" />
          <div className="app-brand__text">
            <div className="app-brand__title">Mini SIEM</div>
            <div className="app-brand__subtitle">威胁检测平台</div>
          </div>
        </div>

        <div className="app-health">
          <Badge status={badge.status} />
          <span className="app-health__text">{badge.text}</span>
          <Tooltip
            title={
              health
                ? `版本 ${health.version} · 规则 ${health.rules_enabled}/${health.rules_loaded} 启用 · 存储 ${health.backend} ${
                    health.storage ? '已连接' : '未连接'
                  }`
                : '暂时无法获取后端信息'
            }
          >
            <SettingOutlined className="app-health__info" />
          </Tooltip>
        </div>

        <Menu
          theme="dark"
          mode="inline"
          className="app-menu"
          selectedKeys={[selectedKey]}
          items={MENU_ITEMS}
        />

        <div className="app-sider__footer">
          <Dropdown menu={userMenu} placement="topRight" trigger={['click']}>
            <div className="app-user" role="button" tabIndex={0}>
              <Space>
                <UserOutlined />
                <Typography.Text className="app-user__name">{username || '管理员'}</Typography.Text>
              </Space>
            </div>
          </Dropdown>
          <Typography.Text type="secondary" className="app-sider__version">
            {health ? `v${health.version}` : 'v-'}
          </Typography.Text>
        </div>
      </Layout.Sider>

      <Layout.Content className="app-content">{children}</Layout.Content>

      <ChangePasswordModal open={passwordOpen} onClose={() => setPasswordOpen(false)} />
    </Layout>
  );
}
