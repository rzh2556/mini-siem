/** 日志检索页面：全文检索 + 多维筛选 + 服务端分页，筛选条件与 URL 查询参数保持同步。 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { ReactNode } from 'react';
import {
  Button,
  Card,
  Col,
  Descriptions,
  Empty,
  Form,
  Input,
  Row,
  Select,
  Table,
  Tag,
  Tooltip,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { fetchLogFilters, searchLogs } from '../api/endpoints';
import type { LogEvent, LogFilters, LogQuery } from '../api/types';
import { formatTime } from '../utils/format';
import UploadLogModal from '../components/UploadLogModal';

/** 可选时间范围（相对时间由后端解析，空值代表不限时间） */
const TIME_RANGES = [
  { label: '不限时间', value: '' },
  { label: '最近 1 小时', value: '1h' },
  { label: '最近 6 小时', value: '6h' },
  { label: '最近 24 小时', value: '24h' },
  { label: '最近 7 天', value: '7d' },
  { label: '最近 30 天', value: '30d' },
];

/** 默认不限时间：检索属于主动查询，默认加 24 小时窗口会导致导入历史日志后“查不到内容” */
const DEFAULT_FROM = '';

/** 筛选表单字段（全部按字符串处理，提交时由后端解析） */
interface LogFilterForm {
  source_type?: string;
  host?: string;
  src_ip?: string;
  user?: string;
  level?: string;
  status_code?: string;
  matched_rule?: string;
  from?: string;
}

/** 根据 HTTP 状态码返回展示颜色 */
function statusColor(code?: number | null): string {
  if (code === undefined || code === null) {
    return 'default';
  }
  if (code >= 500) {
    return 'red';
  }
  if (code >= 400) {
    return 'orange';
  }
  if (code >= 300) {
    return 'blue';
  }
  return 'green';
}

/** 渲染日志检索页面。 */
export default function Logs() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [form] = Form.useForm<LogFilterForm>();
  const [items, setItems] = useState<LogEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState<LogFilters>({ source_types: [], hosts: [], levels: [] });
  const [keyword, setKeyword] = useState('');
  const [uploadOpen, setUploadOpen] = useState(false);

  /** 从 URL 查询参数解析检索条件，默认不限时间 */
  const query: LogQuery = useMemo(() => {
    const statusCode = searchParams.get('status_code');
    const size = Number(searchParams.get('size') ?? 20);
    // 空字符串代表“不限时间”，转成 undefined 后不会作为请求参数发送
    const from = (searchParams.get('from') ?? DEFAULT_FROM) || undefined;
    return {
      q: searchParams.get('q') ?? undefined,
      source_type: searchParams.get('source_type') ?? undefined,
      host: searchParams.get('host') ?? undefined,
      src_ip: searchParams.get('src_ip') ?? undefined,
      user: searchParams.get('user') ?? undefined,
      level: searchParams.get('level') ?? undefined,
      status_code: statusCode ? Number(statusCode) : undefined,
      matched_rule: searchParams.get('matched_rule') ?? undefined,
      from,
      to: searchParams.get('to') ?? undefined,
      sort: searchParams.get('sort') ?? 'timestamp',
      order: searchParams.get('order') === 'asc' ? 'asc' : 'desc',
      page: Number(searchParams.get('page') ?? 1),
      size: Number.isNaN(size) ? 20 : size,
    };
  }, [searchParams]);

  /** 按当前条件检索日志 */
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await searchLogs(query);
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

  /** 加载筛选项（来源类型、主机、等级） */
  const loadFilters = useCallback(() => {
    // 筛选项覆盖最近 30 天，避免导入历史日志后下拉框里看不到对应的来源类型 / 主机
    fetchLogFilters(720)
      .then(setFilters)
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    loadFilters();
  }, [loadFilters]);

  /** 上传解析成功后的处理：刷新筛选项与当前检索结果，让新入库日志立即可见 */
  const handleUploadSuccess = () => {
    loadFilters();
    load();
  };

  // 搜索框与筛选表单跟随 URL 变化（例如从告警页跳转携带 src_ip 时）
  useEffect(() => {
    setKeyword(query.q ?? '');
    form.setFieldsValue({
      source_type: query.source_type,
      host: query.host,
      src_ip: query.src_ip,
      user: query.user,
      level: query.level,
      status_code: query.status_code !== undefined ? String(query.status_code) : undefined,
      matched_rule: query.matched_rule,
      from: query.from ?? DEFAULT_FROM,
    });
  }, [form, query]);

  /** 合并写入 URL 查询参数并触发重新检索，默认回到第一页 */
  const applyParams = useCallback(
    (patch: Record<string, unknown>, resetPage = true) => {
      const next = new URLSearchParams(searchParams);
      Object.entries(patch).forEach(([key, value]) => {
        if (value === undefined || value === null || value === '') {
          next.delete(key);
        } else {
          next.set(key, String(value));
        }
      });
      if (resetPage) {
        next.set('page', '1');
      }
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  /** 提交全文检索关键字 */
  const handleSearchKeyword = (value: string) => {
    applyParams({ q: value.trim() || undefined });
  };

  /** 重置全部检索条件 */
  const handleReset = () => {
    setKeyword('');
    form.resetFields();
    applyParams({
      q: undefined,
      source_type: undefined,
      host: undefined,
      src_ip: undefined,
      user: undefined,
      level: undefined,
      status_code: undefined,
      matched_rule: undefined,
      from: DEFAULT_FROM,
    });
  };

  /** 行展开内容：归一化字段 + 命中规则 + 原始日志 */
  const renderExpanded = (record: LogEvent) => {
    const detailItems: { label: string; value: ReactNode }[] = [
      { label: '事件 ID', value: record.id || '-' },
      { label: '时间', value: formatTime(record.timestamp) },
      { label: '主机', value: record.host || '-' },
      { label: '来源类型', value: record.source_type || '-' },
      { label: '等级', value: record.level || '-' },
      { label: '源 IP', value: record.src_ip || '-' },
      { label: '源端口', value: record.src_port ?? '-' },
      { label: '目标 IP', value: record.dst_ip || '-' },
      { label: '目标端口', value: record.dst_port ?? '-' },
      { label: '用户', value: record.user || '-' },
      { label: '请求方法', value: record.method || '-' },
      { label: 'URL', value: record.url || '-' },
      { label: '路径', value: record.path || '-' },
      { label: '查询串', value: record.query || '-' },
      { label: '状态码', value: record.status_code ?? '-' },
      { label: 'User-Agent', value: record.user_agent || '-' },
      { label: 'Windows 事件 ID', value: record.event_id ?? '-' },
      { label: '日志通道', value: record.channel || '-' },
      { label: '进程', value: record.process || '-' },
      { label: '命令行', value: record.command || '-' },
      { label: '消息', value: record.message || '-' },
      {
        label: '地理位置',
        value: record.geo
          ? [record.geo.country, record.geo.city].filter(Boolean).join(' / ') || '未知'
          : '-',
      },
    ];

    return (
      <div>
        <div className="section-label">归一化字段</div>
        <Descriptions column={{ xs: 1, sm: 2, lg: 3 }} size="small" bordered>
          {detailItems.map((item) => (
            <Descriptions.Item key={item.label} label={item.label}>
              <span style={{ wordBreak: 'break-all' }}>{item.value}</span>
            </Descriptions.Item>
          ))}
        </Descriptions>

        <div className="section-label">命中规则</div>
        {record.matched_rules && record.matched_rules.length > 0 ? (
          record.matched_rules.map((rule) => (
            <Tag key={rule} color="red">
              {rule}
            </Tag>
          ))
        ) : (
          <span style={{ color: '#8b98a5' }}>未命中任何规则</span>
        )}

        {record.tags && record.tags.length > 0 ? (
          <>
            <div className="section-label">标签</div>
            {record.tags.map((tag) => (
              <Tag key={tag} color="blue">
                {tag}
              </Tag>
            ))}
          </>
        ) : null}

        <div className="section-label">原始日志</div>
        <pre className="raw-block">{record.raw || '（无原始内容）'}</pre>
      </div>
    );
  };

  /** 表格列定义 */
  const columns: ColumnsType<LogEvent> = [
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 175,
      render: (value: string) => formatTime(value),
    },
    {
      title: '来源类型',
      dataIndex: 'source_type',
      key: 'source_type',
      width: 110,
      render: (value?: string | null) => (value ? <Tag color="cyan">{value}</Tag> : '-'),
    },
    {
      title: '主机',
      dataIndex: 'host',
      key: 'host',
      width: 140,
      render: (value?: string | null) => value || '-',
    },
    {
      title: '源 IP',
      dataIndex: 'src_ip',
      key: 'src_ip',
      width: 140,
      render: (value?: string | null) => value || '-',
    },
    {
      title: '用户',
      dataIndex: 'user',
      key: 'user',
      width: 110,
      render: (value?: string | null) => value || '-',
    },
    {
      title: '请求',
      key: 'request',
      width: 320,
      render: (_value, record) => {
        const text = [record.method, record.url || record.path].filter(Boolean).join(' ');
        if (!text) {
          return record.message ? (
            <Tooltip title={record.message}>
              <span className="table-cell-ellipsis">{record.message}</span>
            </Tooltip>
          ) : (
            '-'
          );
        }
        return (
          <Tooltip title={text}>
            <span className="table-cell-ellipsis">{text}</span>
          </Tooltip>
        );
      },
    },
    {
      title: '状态码',
      dataIndex: 'status_code',
      key: 'status_code',
      width: 92,
      render: (code?: number | null) =>
        code === undefined || code === null ? '-' : <Tag color={statusColor(code)}>{code}</Tag>,
    },
    {
      title: '命中规则',
      dataIndex: 'matched_rules',
      key: 'matched_rules',
      width: 220,
      render: (rules?: string[] | null) =>
        rules && rules.length > 0 ? (
          <>
            {rules.map((rule) => (
              <Tag key={rule} color="red">
                {rule}
              </Tag>
            ))}
          </>
        ) : (
          '-'
        ),
    },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">日志检索</h2>
          <div className="page-subtitle">支持 AND / OR / NOT 全文语法与多维条件过滤</div>
        </div>
        <div className="page-toolbar">
          <Button type="primary" onClick={() => setUploadOpen(true)}>
            上传日志文件
          </Button>
          <Input.Search
            allowClear
            style={{ width: 320 }}
            placeholder="全文检索，如 failed AND ssh NOT internal"
            value={keyword}
            onChange={(event) => setKeyword(event.target.value)}
            onSearch={handleSearchKeyword}
          />
          <Button onClick={load}>刷新</Button>
          <Button onClick={handleReset}>重置条件</Button>
        </div>
      </div>

      <Card className="filter-bar">
        <Form<LogFilterForm>
          form={form}
          layout="vertical"
          onValuesChange={(_changed, allValues) => applyParams({ ...allValues })}
        >
          <Row gutter={12}>
            <Col xs={12} md={4}>
              <Form.Item name="source_type" label="来源类型">
                <Select
                  allowClear
                  placeholder="全部"
                  options={filters.source_types.map((item) => ({ label: item, value: item }))}
                />
              </Form.Item>
            </Col>
            <Col xs={12} md={4}>
              <Form.Item name="host" label="主机">
                <Select
                  allowClear
                  showSearch
                  placeholder="全部"
                  options={filters.hosts.map((item) => ({ label: item, value: item }))}
                />
              </Form.Item>
            </Col>
            <Col xs={12} md={3}>
              <Form.Item name="level" label="等级">
                <Select
                  allowClear
                  placeholder="全部"
                  options={filters.levels.map((item) => ({ label: item, value: item }))}
                />
              </Form.Item>
            </Col>
            <Col xs={12} md={3}>
              <Form.Item name="status_code" label="状态码">
                <Input allowClear placeholder="如 404" />
              </Form.Item>
            </Col>
            <Col xs={12} md={4}>
              <Form.Item name="src_ip" label="源 IP">
                <Input allowClear placeholder="如 1.2.3.4" />
              </Form.Item>
            </Col>
            <Col xs={12} md={3}>
              <Form.Item name="user" label="用户">
                <Input allowClear placeholder="用户名" />
              </Form.Item>
            </Col>
            <Col xs={12} md={3}>
              <Form.Item name="matched_rule" label="命中规则 ID">
                <Input allowClear placeholder="规则 ID" />
              </Form.Item>
            </Col>
            <Col xs={12} md={3}>
              <Form.Item name="from" label="时间范围">
                <Select options={TIME_RANGES} />
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Card>

      <Card>
        <Table<LogEvent>
          rowKey={(record) => record.id ?? `${record.timestamp}-${record.src_ip ?? ''}-${record.host ?? ''}`}
          size="small"
          loading={loading}
          columns={columns}
          dataSource={items}
          scroll={{ x: 1300 }}
          locale={{ emptyText: <Empty description="暂无符合条件的日志" /> }}
          expandable={{
            expandedRowRender: renderExpanded,
            rowExpandable: () => true,
          }}
          pagination={{
            current: query.page ?? 1,
            pageSize: query.size ?? 20,
            total,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (count) => `共 ${count} 条日志`,
            onChange: (page, size) => applyParams({ page, size }, false),
          }}
        />
      </Card>

      <UploadLogModal
        open={uploadOpen}
        onClose={() => setUploadOpen(false)}
        onSuccess={handleUploadSuccess}
      />
    </div>
  );
}
