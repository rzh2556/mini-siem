/** 应用入口：挂载 React 应用，配置 Ant Design 深色主题与路由容器。 */
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { App as AntdApp, ConfigProvider, theme } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import dayjs from 'dayjs';
import 'dayjs/locale/zh-cn';
import App from './App';
import './styles/global.css';

// 统一使用中文日期格式
dayjs.locale('zh-cn');

const rootElement = document.getElementById('root');

// 说明：此处未启用 React.StrictMode。开发模式下 StrictMode 会额外执行一次
// 副作用清理，而 Leaflet 地图容器被销毁后不会在 StrictMode 的“二次挂载”中重建，
// 会导致攻击地图空白，因此这里直接使用普通渲染。
if (rootElement) {
  ReactDOM.createRoot(rootElement).render(
    <ConfigProvider
      locale={zhCN}
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: '#177ddc',
          colorInfo: '#13c2c2',
          colorBgLayout: '#0f1419',
          colorBgContainer: '#1a222c',
          colorBgElevated: '#1a222c',
          colorBorder: '#2a3441',
          colorBorderSecondary: '#243040',
          colorText: '#e6f0fa',
          colorTextSecondary: '#8b98a5',
          borderRadius: 6,
        },
      }}
    >
      <AntdApp>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </AntdApp>
    </ConfigProvider>,
  );
}
