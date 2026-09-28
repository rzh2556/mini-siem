/** 应用整体布局：左侧导航栏（平台名称 + 后端健康状态）与右侧内容区。 */
import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Badge, Button, Input, Layout, Menu, Modal, Tooltip, Typography, message } from 'antd';
import {
  AlertOutlined,
  DashboardOutlined,
  FileSearchOutlined,
  GlobalOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  SlidersOutlined,
} from '@ant-design/icons';
import { fetchHealth } from '../api/endpoints';
import { loadStoredToken, saveToken } from '../api/client';
import type { HealthResponse } from '../api/types';

/** 侧边导航菜单项 */
const MENU_ITEMS = [
  { key: '/', icon: <DashboardOutlined />, label: <Link to="/">仪表盘</Link> },
  { key: '/map', icon: <GlobalOutlined />, label: <Link to="/map">攻击地图</Link> },
  { key: '/alerts', icon: <AlertOutlined />, label: <Link to="/alerts">告警中心</Link> },
  { key: '/logs', icon: <FileSearchOutlined />, label: <Link to="/logs">日志检索</Link> },
  { key: '/rules', icon: <SlidersOutlined />, label: <Link to="/rules">规则管理</Link> },
];

/** 布局属性 */
interface AppLayoutProps {
  /** 右侧内容区 */
  children: ReactNode;
}

/** 渲染应用框架：左侧固定导航 + 顶部标题健康状态 + 内容区。 */
export default function AppLayout({ children }: AppLayoutProps) {
  const location = useLocation();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthFailed, setHealthFailed] = useState(false);
  const [tokenOpen, setTokenOpen] = useState(false);
  const [tokenDraft, setTokenDraft] = useState('');

  /** 拉取后端健康状态，失败时标记为不可用 */
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
    return { status: 'warning' as const, text: '服务降级（ES 未连接）' };
  };

  const badge = healthBadge();

  /** 打开令牌设置弹窗并回填当前值 */
  const openTokenModal = () => {
    setTokenDraft(loadStoredToken());
    setTokenOpen(true);
  };

  /** 保存令牌到 localStorage 并刷新健康状态 */
  const handleTokenSave = () => {
    saveToken(tokenDraft);
    setTokenOpen(false);
    message.success(tokenDraft.trim() ? '访问令牌已保存' : '访问令牌已清除');
    loadHealth();
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
                ? `版本 ${health.version} · 规则 ${health.rules_enabled}/${health.rules_loaded} 启用 · ES ${
                    health.elasticsearch ? '已连接' : '未连接'
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
          <Button type="text" block icon={<SettingOutlined />} onClick={openTokenModal}>
            设置访问令牌
          </Button>
          <Typography.Text type="secondary" className="app-sider__version">
            {health ? `v${health.version}` : 'v-'}
          </Typography.Text>
        </div>
      </Layout.Sider>

      <Layout.Content className="app-content">{children}</Layout.Content>

      <Modal
        title="设置访问令牌"
        open={tokenOpen}
        onOk={handleTokenSave}
        onCancel={() => setTokenOpen(false)}
        okText="保存"
        cancelText="取消"
        destroyOnClose
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          令牌将保存在浏览器 localStorage 中，请求时以 Authorization: Bearer 头发送。留空表示后端未开启鉴权。
        </Typography.Paragraph>
        <Input.Password
          placeholder="请输入后端 API_TOKEN"
          value={tokenDraft}
          onChange={(event) => setTokenDraft(event.target.value)}
          allowClear
        />
      </Modal>
    </Layout>
  );
}
