/** 告警中心页面：按条件筛选告警，支持详情查看、状态流转与批量关闭。 */
import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Button,
  Card,
  Col,
  Form,
  Input,
  Popconfirm,
  Row,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { Key } from 'react';
import { bulkUpdateAlerts, fetchAlertDetail, fetchAlerts, updateAlert } from '../api/endpoints';
import type { Alert, AlertQuery } from '../api/types';
import AlertDetailDrawer, { STATUS_COLORS, STATUS_LABELS } from '../components/AlertDetailDrawer';
import SeverityTag from '../components/SeverityTag';
import { formatTime } from '../utils/format';

/** 可选时间范围（相对时间由后端解析） */
const TIME_RANGES = [
  { label: '不限时间', value: '' },
  { label: '最近 1 小时', value: '1h' },
  { label: '最近 6 小时', value: '6h' },
  { label: '最近 24 小时', value: '24h' },
  { label: '最近 7 天', value: '7d' },
  { label: '最近 30 天', value: '30d' },
];

/** 严重等级下拉选项 */
const SEVERITY_OPTIONS = [
  { label: '严重', value: 'critical' },
  { label: '高危', value: 'high' },
  { label: '中危', value: 'medium' },
  { label: '低危', value: 'low' },
];

/** 状态下拉选项 */
const STATUS_OPTIONS = [
  { label: '未处理', value: 'open' },
  { label: '已处理', value: 'acknowledged' },
  { label: '已关闭', value: 'closed' },
];

/** 渲染告警中心页面。 */
export default function Alerts() {
  const navigate = useNavigate();
  const [form] = Form.useForm<AlertQuery>();
  const [query, setQuery] = useState<AlertQuery>({ page: 1, size: 20 });
  const [items, setItems] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [selectedKeys, setSelectedKeys] = useState<Key[]>([]);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [detail, setDetail] = useState<Alert | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  /** 按当前条件加载告警列表 */
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchAlerts(query);
      setItems(data.items);
      setTotal(data.total);
    } catch {
      // 错误提示已由 axios 拦截器统一处理
    } finally {
      setLoading(false);
    }
  }, [query]);

  useEffect(() => {
    load();
  }, [load]);

  /** 提交筛选条件，重置到第一页 */
  const handleSearch = (values: AlertQuery) => {
    setQuery({ ...values, page: 1, size: query.size ?? 20 });
  };

  /** 重置筛选条件 */
  const handleReset = () => {
    form.resetFields();
    setQuery({ page: 1, size: query.size ?? 20 });
  };

  /** 打开告警详情抽屉，并拉取最新详情数据 */
  const openDetail = (record: Alert) => {
    setDetail(record);
    setDrawerOpen(true);
    if (!record.id) {
      return;
    }
    setDetailLoading(true);
    fetchAlertDetail(record.id)
      .then((data) => setDetail(data))
      .catch(() => undefined)
      .finally(() => setDetailLoading(false));
  };

  /** 单条告警状态变更 */
  const changeStatus = (record: Alert, status: 'acknowledged' | 'closed') => {
    if (!record.id) {
      return;
    }
    const comment = status === 'acknowledged' ? '已确认' : '已关闭';
    updateAlert(record.id, { status, comment })
      .then(() => {
        message.success(`告警已标记为${STATUS_LABELS[status]}`);
        load();
      })
      .catch(() => undefined);
  };

  /** 批量关闭选中的告警 */
  const handleBulkClose = () => {
    if (selectedKeys.length === 0) {
      message.warning('请先选择需要关闭的告警');
      return;
    }
    bulkUpdateAlerts(selectedKeys.map((key) => String(key)), 'closed')
      .then((result) => {
        message.success(`已关闭 ${result.updated} 条告警`);
        setSelectedKeys([]);
        load();
      })
      .catch(() => undefined);
  };

  /** 跳转到日志检索页并带上源 IP 条件 */
  const gotoLogs = (srcIp: string) => {
    navigate(`/logs?src_ip=${encodeURIComponent(srcIp)}`);
  };

  /** 表格列定义 */
  const columns: ColumnsType<Alert> = [
    {
      title: '等级',
      dataIndex: 'severity',
      key: 'severity',
      width: 90,
      render: (severity: Alert['severity']) => <SeverityTag severity={severity} />,
    },
    {
      title: '告警名称',
      dataIndex: 'rule_name',
      key: 'rule_name',
      width: 180,
      ellipsis: true,
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      width: 260,
      render: (text?: string | null) =>
        text ? (
          <Typography.Text type="secondary" ellipsis={{ tooltip: text }} style={{ maxWidth: 240 }}>
            {text}
          </Typography.Text>
        ) : (
          '-'
        ),
    },
    {
      title: '源 IP',
      dataIndex: 'src_ip',
      key: 'src_ip',
      width: 160,
      render: (_value, record) =>
        record.src_ip ? (
          <Space size={4}>
            <Button type="link" size="small" style={{ padding: 0 }} onClick={() => gotoLogs(record.src_ip as string)}>
              {record.src_ip}
            </Button>
            {record.geo?.country_code ? <Tag color="blue">{record.geo.country_code}</Tag> : null}
          </Space>
        ) : (
          '-'
        ),
    },
    {
      title: '主机',
      dataIndex: 'host',
      key: 'host',
      width: 130,
      render: (host?: string | null) => host || '-',
    },
    {
      title: '关联次数',
      dataIndex: 'count',
      key: 'count',
      width: 96,
      sorter: (a, b) => a.count - b.count,
    },
    {
      title: '首次发现',
      dataIndex: 'first_seen',
      key: 'first_seen',
      width: 170,
      render: (value: string) => formatTime(value),
    },
    {
      title: '最近发现',
      dataIndex: 'last_seen',
      key: 'last_seen',
      width: 170,
      render: (value: string) => formatTime(value),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: Alert['status']) => (
        <Tag color={STATUS_COLORS[status]}>{STATUS_LABELS[status]}</Tag>
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 210,
      fixed: 'right',
      render: (_value, record) => (
        <Space size={4}>
          <Button type="link" size="small" onClick={() => openDetail(record)}>
            详情
          </Button>
          <Button
            type="link"
            size="small"
            disabled={record.status !== 'open'}
            onClick={() => changeStatus(record, 'acknowledged')}
          >
            已处理
          </Button>
          <Popconfirm
            title="确认关闭该告警？"
            okText="关闭"
            cancelText="取消"
            onConfirm={() => changeStatus(record, 'closed')}
          >
            <Button type="link" size="small" disabled={record.status === 'closed'}>
              关闭
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">告警中心</h2>
          <div className="page-subtitle">按规则、来源、时间等维度筛选并处理安全告警</div>
        </div>
        <div className="page-toolbar">
          <Button onClick={load}>刷新</Button>
          <Button type="primary" danger onClick={handleBulkClose}>
            批量关闭{selectedKeys.length > 0 ? `（${selectedKeys.length}）` : ''}
          </Button>
        </div>
      </div>

      <Card className="filter-bar">
        <Form<AlertQuery> form={form} layout="vertical" onFinish={handleSearch}>
          <Row gutter={12}>
            <Col xs={12} md={4}>
              <Form.Item name="status" label="状态">
                <Select allowClear placeholder="全部状态" options={STATUS_OPTIONS} />
              </Form.Item>
            </Col>
            <Col xs={12} md={4}>
              <Form.Item name="severity" label="严重等级">
                <Select allowClear placeholder="全部等级" options={SEVERITY_OPTIONS} />
              </Form.Item>
            </Col>
            <Col xs={12} md={4}>
              <Form.Item name="rule_id" label="规则 ID">
                <Input allowClear placeholder="如 ssh_brute_force" />
              </Form.Item>
            </Col>
            <Col xs={12} md={4}>
              <Form.Item name="src_ip" label="源 IP">
                <Input allowClear placeholder="如 1.2.3.4" />
              </Form.Item>
            </Col>
            <Col xs={12} md={4}>
              <Form.Item name="host" label="主机">
                <Input allowClear placeholder="主机名" />
              </Form.Item>
            </Col>
            <Col xs={12} md={4}>
              <Form.Item name="from" label="时间范围">
                <Select options={TIME_RANGES} placeholder="不限时间" />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="keyword" label="关键词">
                <Input allowClear placeholder="按告警名称或描述模糊搜索" />
              </Form.Item>
            </Col>
            <Col xs={24} md={16}>
              <Form.Item label=" ">
                <Space>
                  <Button type="primary" htmlType="submit">
                    查询
                  </Button>
                  <Button onClick={handleReset}>重置</Button>
                </Space>
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Card>

      <Card>
        <Table<Alert>
          rowKey={(record) => record.id ?? `${record.rule_id}-${record.group_key}-${record.last_seen}`}
          size="small"
          loading={loading}
          columns={columns}
          dataSource={items}
          scroll={{ x: 1500 }}
          locale={{ emptyText: '暂无符合条件的告警' }}
          rowSelection={{
            selectedRowKeys: selectedKeys,
            onChange: (keys) => setSelectedKeys(keys),
          }}
          pagination={{
            current: query.page ?? 1,
            pageSize: query.size ?? 20,
            total,
            showSizeChanger: true,
            showTotal: (count) => `共 ${count} 条告警`,
            onChange: (page, size) => setQuery((prev) => ({ ...prev, page, size })),
          }}
        />
      </Card>

      <AlertDetailDrawer
        open={drawerOpen}
        alert={detail}
        loading={detailLoading}
        onClose={() => setDrawerOpen(false)}
        onUpdated={load}
      />
    </div>
  );
}
