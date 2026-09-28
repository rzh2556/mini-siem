/** 系统设置页：查看系统信息、管理访问令牌与运行参数、查看部署配置。 */
import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Popconfirm,
  Row,
  Select,
  Space,
  Statistic,
  Switch,
  Tag,
  Typography,
  message,
} from 'antd';
import { ReloadOutlined, SaveOutlined } from '@ant-design/icons';
import {
  fetchSettings,
  fetchSystemInfo,
  regenerateAgentToken,
  saveSettings,
} from '../api/endpoints';
import type { EditableSettings, ReadOnlySettings, SystemInfo } from '../api/types';

/** 最小告警等级选项 */
const SEVERITY_OPTIONS = [
  { label: '严重 critical', value: 'critical' },
  { label: '高危 high', value: 'high' },
  { label: '中危 medium', value: 'medium' },
  { label: '低危 low', value: 'low' },
];

/** 日志级别选项 */
const LOG_LEVEL_OPTIONS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'].map((value) => ({
  label: value,
  value,
}));

/** 字节数转可读文本。 */
function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

/** 秒数转运行时长（天/小时/分钟）。 */
function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const parts: string[] = [];
  if (days) {
    parts.push(`${days} 天`);
  }
  if (hours) {
    parts.push(`${hours} 小时`);
  }
  if (minutes || parts.length === 0) {
    parts.push(`${minutes} 分钟`);
  }
  return parts.join(' ');
}

/** 渲染系统设置后台页面。 */
export default function AdminSettings() {
  const [form] = Form.useForm<EditableSettings>();
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [readOnly, setReadOnly] = useState<ReadOnlySettings | null>(null);
  const [restartKeys, setRestartKeys] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  /** 加载系统信息与全部配置 */
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [settingsResult, infoResult] = await Promise.all([fetchSettings(), fetchSystemInfo()]);
      form.setFieldsValue(settingsResult.editable);
      setReadOnly(settingsResult.read_only);
      setRestartKeys(settingsResult.restart_required_keys);
      setInfo(infoResult);
    } catch {
      // 错误提示由 axios 拦截器统一处理
    } finally {
      setLoading(false);
    }
  }, [form]);

  useEffect(() => {
    load();
  }, [load]);

  /** 保存全部可编辑参数 */
  const handleSave = async () => {
    const values = await form.validateFields();
    setSaving(true);
    try {
      const result = await saveSettings(values);
      message.success(result.message);
      form.setFieldsValue(result.editable);
      const systemInfo = await fetchSystemInfo();
      setInfo(systemInfo);
    } catch {
      // 错误提示由 axios 拦截器统一处理
    } finally {
      setSaving(false);
    }
  };

  /** 重新生成 Agent 采集令牌 */
  const handleRegenerateAgentToken = async () => {
    const result = await regenerateAgentToken();
    form.setFieldValue('agent_token', result.agent_token);
    message.success('Agent 采集令牌已重新生成，请同步更新各 Agent 配置');
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">系统设置</h2>
          <div className="page-subtitle">查看系统状态、管理访问令牌与检测运行参数</div>
        </div>
        <div className="page-toolbar">
          <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
            刷新
          </Button>
          <Button type="primary" icon={<SaveOutlined />} loading={saving} onClick={handleSave}>
            保存配置
          </Button>
        </div>
      </div>

      {restartKeys.length > 0 ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="部分参数修改后需要重启服务才能完全生效"
          description={`涉及参数：${restartKeys.join('、')}。其余参数保存后立即生效。`}
        />
      ) : null}

      <Row gutter={16}>
        <Col xs={24} lg={8}>
          <Card title="系统信息" size="small" style={{ marginBottom: 16 }} loading={loading}>
            {info ? (
              <>
                <Row gutter={16} style={{ marginBottom: 12 }}>
                  <Col span={8}>
                    <div className="mini-stat">
                      <div className="mini-stat__title">存储状态</div>
                      <Tag color={info.storage_ok ? 'success' : 'error'} style={{ marginTop: 4 }}>
                        {info.storage_ok ? '正常' : '未连接'}
                      </Tag>
                    </div>
                  </Col>
                  <Col span={8}>
                    <Statistic title="启用规则" value={info.rules_enabled} suffix={`/ ${info.rules_loaded}`} />
                  </Col>
                  <Col span={8}>
                    <Statistic title="运行时长" value={formatUptime(info.uptime_seconds)} />
                  </Col>
                </Row>
                <Descriptions column={1} size="small" labelStyle={{ width: 110 }}>
                  <Descriptions.Item label="版本">v{info.version}</Descriptions.Item>
                  <Descriptions.Item label="存储后端">{info.backend}</Descriptions.Item>
                  <Descriptions.Item label="主机名">{info.hostname}</Descriptions.Item>
                  <Descriptions.Item label="操作系统">{info.platform}</Descriptions.Item>
                  <Descriptions.Item label="Python">{info.python}</Descriptions.Item>
                  <Descriptions.Item label="业务库占用">{formatBytes(info.business_db_bytes)}</Descriptions.Item>
                  <Descriptions.Item label="系统库占用">{formatBytes(info.system_db_bytes)}</Descriptions.Item>
                  <Descriptions.Item label="服务器时间">{info.server_time}</Descriptions.Item>
                </Descriptions>
              </>
            ) : null}
          </Card>

          <Card title="部署参数（只读）" size="small">
            <Descriptions column={1} size="small" labelStyle={{ width: 110 }}>
              <Descriptions.Item label="存储后端">{readOnly?.storage_backend ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="SQLite 路径">{readOnly?.sqlite_path ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="ES 地址">{readOnly?.es_url ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="前端目录">
                {readOnly?.frontend_dist || '未启用托管'}
              </Descriptions.Item>
              <Descriptions.Item label="规则目录">{readOnly?.rules_dir ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="系统库路径">{readOnly?.system_db_path ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="管理员账号">{readOnly?.admin_username ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="登录有效期">
                {readOnly ? `${readOnly.token_expire_hours} 小时` : '-'}
              </Descriptions.Item>
            </Descriptions>
            <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 8, marginBottom: 0 }}>
              这些参数在部署配置（.env / 环境变量）中修改后重启服务生效。
            </Typography.Paragraph>
          </Card>
        </Col>

        <Col xs={24} lg={16}>
          <Form form={form} layout="vertical">
            <Card title="访问令牌" size="small" style={{ marginBottom: 16 }}>
              <Form.Item
                name="agent_token"
                label="Agent 采集令牌（X-Agent-Token）"
                extra="所有采集 Agent 必须携带此令牌上报；重新生成后旧令牌立即失效。"
              >
                <Input.Password autoComplete="new-password" />
              </Form.Item>
              <Popconfirm
                title="重新生成 Agent 采集令牌？"
                description="生成后需同步修改每台主机 Agent 的 config.yml，否则上报会被拒绝。"
                okText="确认生成"
                cancelText="取消"
                onConfirm={handleRegenerateAgentToken}
              >
                <Button danger>重新生成 Agent 令牌</Button>
              </Popconfirm>

              <Form.Item
                name="api_token"
                label="第三方 API 令牌（可选）"
                style={{ marginTop: 16 }}
                extra="设置后可用该令牌作为 Bearer 令牌调用数据查询接口；留空则只能通过登录访问。"
              >
                <Input.Password
                  placeholder="留空表示仅允许登录后的浏览器访问"
                  autoComplete="new-password"
                />
              </Form.Item>
            </Card>

            <Card title="检测与降噪" size="small" style={{ marginBottom: 16 }}>
              <Space wrap size={20} align="start">
                <Form.Item
                  name="es_retention_days"
                  label="日志保留天数"
                  extra="超期日志由后台任务自动清理，告警不受影响。"
                >
                  <InputNumber min={1} max={3650} addonAfter="天" style={{ width: 200 }} />
                </Form.Item>
                <Form.Item
                  name="alert_cooldown"
                  label="告警聚合冷却"
                  extra="同规则同分组冷却窗口内只聚合为一条告警。"
                >
                  <InputNumber min={0} addonAfter="秒" style={{ width: 200 }} />
                </Form.Item>
                <Form.Item name="min_alert_severity" label="最低告警等级" extra="低于该等级的命中不产生告警。">
                  <Select options={SEVERITY_OPTIONS} style={{ width: 200 }} />
                </Form.Item>
              </Space>
              <Form.Item
                name="ip_whitelist"
                label="源 IP 白名单"
                extra="多个 IP 用英文逗号分隔，来自这些 IP 的事件不产生告警（仅支持精确 IP，不支持网段）。"
              >
                <Input placeholder="如 1.2.3.4,5.6.7.8" />
              </Form.Item>
              <Form.Item name="ignore_internal_src" valuePropName="checked" label="忽略内网攻击源">
                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
              </Form.Item>
            </Card>

            <Card title="GeoIP 与系统" size="small" style={{ marginBottom: 16 }}>
              <Form.Item
                name="geoip_db_path"
                label="GeoIP 数据库路径（.mmdb）"
                extra="修改路径后需重启服务生效；留空且开启在线兜底时将使用在线查询。"
              >
                <Input placeholder="如 geoip/GeoLite2-City.mmdb" />
              </Form.Item>
              <Form.Item name="geoip_online_fallback" valuePropName="checked" label="无本地库时使用在线地理位置查询">
                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
              </Form.Item>
              <Space wrap size={20} align="start">
                <Form.Item name="log_level" label="日志级别" style={{ minWidth: 200 }}>
                  <Select options={LOG_LEVEL_OPTIONS} style={{ width: 200 }} />
                </Form.Item>
                <Form.Item
                  name="cors_origins"
                  label="允许的跨域来源"
                  extra="多个来源用逗号分隔；修改后需重启服务生效。"
                  style={{ minWidth: 320 }}
                >
                  <Input placeholder="如 http://localhost:5173" style={{ width: 320 }} />
                </Form.Item>
              </Space>
            </Card>

            <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
              提示：修改密码请点击左下角用户名 →「修改密码」；忘记密码可在服务器 backend 目录执行
              <Typography.Text code>python reset_admin.py</Typography.Text> 重置。
            </Typography.Paragraph>
          </Form>
        </Col>
      </Row>
    </div>
  );
}
