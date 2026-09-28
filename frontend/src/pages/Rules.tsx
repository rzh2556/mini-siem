/** 规则管理页面：查看检测规则、在线启停与调整等级、重新加载规则文件。 */
import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Button, Card, Select, Space, Switch, Table, Tag, Typography, message } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { fetchRules, reloadRules, updateRule } from '../api/endpoints';
import type { Rule, RuleType, Severity } from '../api/types';
import SeverityTag from '../components/SeverityTag';
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
  const replaceRule = (updated: Rule) => {
    const next = items.map((item) => (item.id === updated.id ? updated : item));
    setItems(next);
    setEnabledCount(next.filter((item) => item.enabled).length);
  };

  /** 切换规则启用状态 */
  const handleToggleEnabled = (rule: Rule, enabled: boolean) => {
    updateRule(rule.id, { enabled })
      .then((updated) => {
        replaceRule(updated);
        message.success(`规则「${rule.name}」已${enabled ? '启用' : '停用'}`);
      })
      .catch(() => undefined);
  };

  /** 在线调整规则严重等级 */
  const handleChangeSeverity = (rule: Rule, severity: Severity) => {
    updateRule(rule.id, { severity })
      .then((updated) => {
        replaceRule(updated);
        message.success(`规则「${rule.name}」等级已更新`);
      })
      .catch(() => undefined);
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
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 110,
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
      width: 180,
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
      title: '标签',
      dataIndex: 'tags',
      key: 'tags',
      width: 180,
      render: (tags: string[]) =>
        tags && tags.length > 0
          ? tags.map((tag) => (
              <Tag key={tag} color="blue">
                {tag}
              </Tag>
            ))
          : '-',
    },
    {
      title: '阈值信息',
      key: 'threshold',
      width: 220,
      render: (_value, record) => thresholdText(record),
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 100,
      fixed: 'right',
      render: (enabled: boolean, record) => (
        <Switch
          checked={enabled}
          checkedChildren="启用"
          unCheckedChildren="停用"
          onChange={(checked) => handleToggleEnabled(record, checked)}
        />
      ),
    },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">规则管理</h2>
          <div className="page-subtitle">
            共 {total} 条规则，已启用 {enabledCount} 条；修改立即生效，无需重启服务
          </div>
        </div>
        <div className="page-toolbar">
          <Button onClick={load}>刷新</Button>
          <Button type="primary" loading={reloading} onClick={handleReload}>
            重新加载规则文件
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
          scroll={{ x: 1400 }}
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
    </div>
  );
}
