/** 规则管理页面：查看规则、启停/调整等级、新增编辑删除自定义规则、导入 Sigma、热加载。 */
import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Button,
  Card,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import {
  DeleteOutlined,
  EditOutlined,
  ImportOutlined,
  PlusOutlined,
  QuestionCircleOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import {
  fetchRules,
  reloadRules,
  removeRule,
  updateRule,
} from '../api/endpoints';
import type { Rule, RuleType, Severity } from '../api/types';
import RuleEditModal from '../components/RuleEditModal';
import RuleFormatHelpDrawer from '../components/RuleFormatHelpDrawer';
import SeverityTag from '../components/SeverityTag';
import SigmaImportModal from '../components/SigmaImportModal';
import { formatSeconds } from '../utils/format';

/** 规则类型 -> 中文文案 */
const TYPE_LABELS: Record<RuleType, string> = {
  match: '特征匹配',
  threshold: '阈值统计',
  first_seen: '首次出现',
};

/** 严重等级下拉选项 */
const SEVERITY_OPTIONS = [
  { label: '严重', value: 'critical' },
  { label: '高危', value: 'high' },
  { label: '中危', value: 'medium' },
  { label: '低危', value: 'low' },
];

/** 把规则阈值配置转成中文描述 */
function thresholdText(rule: Rule): string {
  if (!rule.threshold) {
    return '-';
  }
  const { count, window, group_by } = rule.threshold;
  return `${formatSeconds(window)}内 ${count} 次，按 ${group_by.join('、')} 分组`;
}

/** 渲染 JSON 代码块，空值显示占位文案 */
function renderJson(value: unknown, emptyText = '无'): ReactNode {
  const isEmpty =
    value === null ||
    value === undefined ||
    (Array.isArray(value) && value.length === 0) ||
    (typeof value === 'object' && !Array.isArray(value) && Object.keys(value as object).length === 0);
  if (isEmpty) {
    return <Typography.Text type="secondary">{emptyText}</Typography.Text>;
  }
  return <pre className="json-block">{JSON.stringify(value, null, 2)}</pre>;
}

/** 渲染规则管理页面。 */
export default function Rules() {
  const [items, setItems] = useState<Rule[]>([]);
  const [total, setTotal] = useState(0);
  const [enabledCount, setEnabledCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [sigmaOpen, setSigmaOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  /** 加载全部规则 */
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchRules();
      setItems(data.items);
      setTotal(data.total);
      setEnabledCount(data.enabled);
    } catch {
      // 错误提示已由 axios 拦截器统一处理
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  /** 用后端返回的最新规则替换本地条目，并同步启用数量 */
  const replaceRuleState = (updated: Rule) => {
    const next = items.map((item) => (item.id === updated.id ? updated : item));
    setItems(next);
    setEnabledCount(next.filter((item) => item.enabled).length);
  };

  /** 切换规则启用状态 */
  const handleToggleEnabled = (rule: Rule, enabled: boolean) => {
    updateRule(rule.id, { enabled })
      .then((updated) => {
        replaceRuleState(updated);
        message.success(`规则「${rule.name}」已${enabled ? '启用' : '停用'}`);
      })
      .catch(() => undefined);
  };

  /** 在线调整规则严重等级 */
  const handleChangeSeverity = (rule: Rule, severity: Severity) => {
    updateRule(rule.id, { severity })
      .then((updated) => {
        replaceRuleState(updated);
        message.success(`规则「${rule.name}」等级已更新`);
      })
      .catch(() => undefined);
  };

  /** 删除自定义规则并刷新列表 */
  const handleDelete = (rule: Rule) => {
    removeRule(rule.id)
      .then(() => {
        message.success(`规则「${rule.name}」已删除`);
        load();
      })
      .catch(() => undefined);
  };

  /** 打开新增规则弹窗 */
  const handleCreate = () => {
    setEditingRule(null);
    setEditOpen(true);
  };

  /** 打开编辑自定义规则弹窗 */
  const handleEdit = (rule: Rule) => {
    setEditingRule(rule);
    setEditOpen(true);
  };

  /** 触发后端重新加载规则文件 */
  const handleReload = () => {
    setReloading(true);
    reloadRules()
      .then((result) => {
        message.success(`规则文件已重新加载，共 ${result.loaded} 条`);
        load();
      })
      .catch(() => undefined)
      .finally(() => setReloading(false));
  };

  /** 表格列定义 */
  const columns: ColumnsType<Rule> = [
    {
      title: '规则 ID',
      dataIndex: 'id',
      key: 'id',
      width: 200,
      render: (id: string) => <Typography.Text copyable>{id}</Typography.Text>,
    },
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      width: 200,
      ellipsis: true,
    },
    {
      title: '来源',
      dataIndex: 'managed',
      key: 'managed',
      width: 100,
      render: (managed: boolean) =>
        managed ? <Tag color="geekblue">自定义</Tag> : <Tag>内置</Tag>,
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      render: (type: RuleType) => TYPE_LABELS[type] ?? type,
    },
    {
      title: '严重等级',
      dataIndex: 'severity',
      key: 'severity',
      width: 150,
      render: (severity: Severity, record) => (
        <Space size={6}>
          <SeverityTag severity={severity} />
          <Select
            size="small"
            style={{ width: 84 }}
            value={severity}
            options={SEVERITY_OPTIONS}
            onChange={(value: Severity) => handleChangeSeverity(record, value)}
          />
        </Space>
      ),
    },
    {
      title: '日志类型',
      dataIndex: 'log_types',
      key: 'log_types',
      width: 170,
      render: (types: string[]) =>
        types && types.length > 0
          ? types.map((type) => (
              <Tag key={type} color="cyan">
                {type}
              </Tag>
            ))
          : '-',
    },
    {
      title: '阈值信息',
      key: 'threshold',
      width: 210,
      render: (_value, record) => thresholdText(record),
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 90,
      render: (enabled: boolean, record) => (
        <Switch
          checked={enabled}
          checkedChildren="启用"
          unCheckedChildren="停用"
          onChange={(checked) => handleToggleEnabled(record, checked)}
        />
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 110,
      fixed: 'right',
      render: (_value, record) =>
        record.managed ? (
          <Space size={4}>
            <Tooltip title="编辑">
              <Button size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)} />
            </Tooltip>
            <Popconfirm
              title={`删除规则「${record.name}」？`}
              description="删除后立即生效，可重新创建或再次导入。"
              okText="删除"
              okButtonProps={{ danger: true }}
              cancelText="取消"
              onConfirm={() => handleDelete(record)}
            >
              <Tooltip title="删除">
                <Button size="small" danger icon={<DeleteOutlined />} />
              </Tooltip>
            </Popconfirm>
          </Space>
        ) : (
          <Tooltip title="内置规则仅支持启停与等级调整，不能编辑或删除">
            <Tag style={{ marginInlineStart: 8 }}>只读</Tag>
          </Tooltip>
        ),
    },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">规则管理</h2>
          <div className="page-subtitle">
            共 {total} 条规则，已启用 {enabledCount} 条；支持可视化新增、YAML 文件热加载与 Sigma 规则导入
          </div>
        </div>
        <div className="page-toolbar">
          <Button icon={<QuestionCircleOutlined />} onClick={() => setHelpOpen(true)}>
            规则格式说明
          </Button>
          <Button icon={<ImportOutlined />} onClick={() => setSigmaOpen(true)}>
            导入 Sigma 规则
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
            新增规则
          </Button>
          <Button onClick={load}>刷新</Button>
          <Button loading={reloading} onClick={handleReload}>
            重新加载
          </Button>
        </div>
      </div>

      <Card>
        <Table<Rule>
          rowKey="id"
          size="small"
          loading={loading}
          columns={columns}
          dataSource={items}
          scroll={{ x: 1560 }}
          locale={{ emptyText: '暂无规则' }}
          expandable={{
            expandedRowRender: (record) => (
              <div>
                <div className="section-label">规则描述</div>
                <Typography.Paragraph style={{ marginBottom: 0 }}>
                  {record.description || '无描述'}
                </Typography.Paragraph>

                <div className="section-label">匹配条件 all_of（需全部满足）</div>
                {renderJson(record.all_of, '无 all_of 条件')}

                <div className="section-label">匹配条件 any_of（满足任一即可）</div>
                {renderJson(record.any_of, '无 any_of 条件')}

                {record.time_window ? (
                  <>
                    <div className="section-label">时间窗条件</div>
                    {renderJson(record.time_window, '无时间窗条件')}
                  </>
                ) : null}

                {record.type === 'threshold' ? (
                  <>
                    <div className="section-label">阈值配置</div>
                    {renderJson(record.threshold, '无阈值配置')}
                  </>
                ) : null}

                {record.type === 'first_seen' ? (
                  <>
                    <div className="section-label">首次出现配置</div>
                    {renderJson(
                      {
                        field: record.first_seen_field,
                        lookback: record.first_seen_lookback,
                      },
                      '无首次出现配置',
                    )}
                  </>
                ) : null}

                <div className="section-label">抑制配置 suppression</div>
                {renderJson(record.suppression, '无抑制配置')}
              </div>
            ),
          }}
        />
      </Card>

      <RuleEditModal
        open={editOpen}
        initial={editingRule}
        onClose={() => setEditOpen(false)}
        onSaved={load}
      />
      <SigmaImportModal open={sigmaOpen} onClose={() => setSigmaOpen(false)} onImported={load} />
      <RuleFormatHelpDrawer open={helpOpen} onClose={() => setHelpOpen(false)} />
    </div>
  );
}
