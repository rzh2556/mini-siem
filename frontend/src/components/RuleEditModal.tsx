/** 规则新增/编辑弹窗：通过表单组装规则条件，保存为后台自定义规则。 */
import { useEffect, useMemo, useState } from 'react';
import {
  AutoComplete,
  Button,
  Divider,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Typography,
  message,
} from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { createRule, replaceRule } from '../api/endpoints';
import type { Rule, RuleCondition, RuleType, Severity } from '../api/types';

/** 严重等级选项 */
const SEVERITY_OPTIONS = [
  { label: '严重', value: 'critical' },
  { label: '高危', value: 'high' },
  { label: '中危', value: 'medium' },
  { label: '低危', value: 'low' },
];

/** 规则类型选项 */
const TYPE_OPTIONS = [
  { label: '特征匹配（命中即告警）', value: 'match' },
  { label: '阈值统计（窗口内达次数）', value: 'threshold' },
  { label: '首次出现（回溯期内首次）', value: 'first_seen' },
];

/** 常见日志类型 */
const LOG_TYPE_OPTIONS = ['nginx', 'apache', 'ssh', 'windows', 'syslog', 'linux', 'any'].map(
  (value) => ({ label: value, value }),
);

/** 条件运算符选项（值与后端 RuleCondition 字段对应） */
const OPERATOR_OPTIONS = [
  { label: '正则匹配 regex', value: 'regex' },
  { label: '等于 equals', value: 'equals' },
  { label: '包含 contains', value: 'contains' },
  { label: '属于列表 in（逗号分隔）', value: 'in' },
  { label: '不属于列表 not_in（逗号分隔）', value: 'not_in' },
  { label: '大于 gt', value: 'gt' },
  { label: '小于 lt', value: 'lt' },
];

/** 常用字段提示，供输入参考 */
const FIELD_SUGGESTIONS = [
  'raw', 'message', 'host', 'source_type', 'level', 'src_ip', 'dst_ip', 'user',
  'method', 'url', 'path', 'status_code', 'user_agent', 'event_id', 'channel',
  'process', 'command',
].map((value) => ({ label: value, value }));

/** 编辑表单内部使用的扁平化条件结构 */
interface FlatCondition {
  field: string;
  op: string;
  value: string;
}

interface RuleFormValues {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  severity: Severity;
  type: RuleType;
  log_types: string[];
  tags: string[];
  all_of: FlatCondition[];
  any_of: FlatCondition[];
  threshold_count?: number;
  threshold_window?: number;
  threshold_groupby?: string[];
  first_seen_field?: string;
  first_seen_lookback?: number;
  sup_cooldown?: number;
  sup_ignore_internal?: boolean;
  sup_ignore_ips?: string[];
}

interface RuleEditModalProps {
  open: boolean;
  /** 传入已有规则表示编辑；null 表示新增 */
  initial: Rule | null;
  onClose: () => void;
  onSaved: () => void;
}

/** 把数字样的字符串转成数字，其余保持字符串。 */
function smartValue(raw: string): string | number {
  const text = raw.trim();
  if (/^-?\d+$/.test(text)) {
    return Number(text);
  }
  return text;
}

/** 把扁平化条件转换为后端 RuleCondition；字段缺失的条件被跳过。 */
function buildConditions(conditions: FlatCondition[] | undefined): RuleCondition[] {
  return (conditions ?? [])
    .filter((item) => item && item.field.trim() && item.op)
    .map((item) => {
      const condition: RuleCondition = { field: item.field.trim() };
      const text = item.value ?? '';
      if (item.op === 'in' || item.op === 'not_in') {
        const list = text
          .split(/[,，]/)
          .map((part) => part.trim())
          .filter(Boolean)
          .map(smartValue);
        if (item.op === 'in') {
          condition.in = list;
        } else {
          condition.not_in = list;
        }
      } else if (item.op === 'gt' || item.op === 'lt') {
        const numeric = Number(text);
        if (item.op === 'gt') {
          condition.gt = Number.isFinite(numeric) ? numeric : 0;
        } else {
          condition.lt = Number.isFinite(numeric) ? numeric : 0;
        }
      } else if (item.op === 'equals') {
        condition.equals = smartValue(text);
      } else if (item.op === 'regex') {
        condition.regex = text;
      } else {
        condition.contains = text;
      }
      return condition;
    });
}

/** 把后端条件列表扁平化为表单结构。 */
function flattenConditions(conditions: RuleCondition[] | undefined): FlatCondition[] {
  return (conditions ?? []).map((condition) => {
    let op = 'contains';
    let value = '';
    if (condition.regex !== undefined && condition.regex !== null) {
      op = 'regex';
      value = String(condition.regex);
    } else if (condition.equals !== undefined && condition.equals !== null) {
      op = 'equals';
      value = String(condition.equals);
    } else if (condition.contains !== undefined && condition.contains !== null) {
      op = 'contains';
      value = String(condition.contains);
    } else if (condition.in) {
      op = 'in';
      value = condition.in.map(String).join(',');
    } else if (condition.not_in) {
      op = 'not_in';
      value = condition.not_in.map(String).join(',');
    } else if (condition.gt !== undefined && condition.gt !== null) {
      op = 'gt';
      value = String(condition.gt);
    } else if (condition.lt !== undefined && condition.lt !== null) {
      op = 'lt';
      value = String(condition.lt);
    }
    return { field: condition.field, op, value };
  });
}

/** 渲染条件编辑器（all_of / any_of 共用）。 */
function ConditionList({ name, label, hint }: { name: 'all_of' | 'any_of'; label: string; hint: string }) {
  return (
    <>
      <Divider orientation="left" style={{ margin: '8px 0' }}>
        {label}
      </Divider>
      <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 8 }}>
        {hint}
      </Typography.Paragraph>
      <Form.List name={name}>
        {(fields, { add, remove }) => (
          <Space direction="vertical" style={{ display: 'flex' }} size={8}>
            {fields.map((field) => (
              <Space key={field.key} align="baseline" wrap>
                <Form.Item
                  name={[field.name, 'field']}
                  rules={[{ required: true, message: '字段名' }]}
                  style={{ marginBottom: 0 }}
                >
                  <AutoComplete
                    style={{ width: 170 }}
                    options={FIELD_SUGGESTIONS}
                    placeholder="字段名"
                    filterOption={(input, option) =>
                      (option?.value ?? '').toLowerCase().includes(input.toLowerCase())
                    }
                  />
                </Form.Item>
                <Form.Item name={[field.name, 'op']} style={{ marginBottom: 0 }}>
                  <Select style={{ width: 220 }} options={OPERATOR_OPTIONS} placeholder="运算" />
                </Form.Item>
                <Form.Item name={[field.name, 'value']} style={{ marginBottom: 0, width: 260 }}>
                  <Input placeholder="匹配值（in/not_in 用逗号分隔多个值）" />
                </Form.Item>
                <Button
                  type="text"
                  danger
                  icon={<DeleteOutlined />}
                  onClick={() => remove(field.name)}
                />
              </Space>
            ))}
            <Button type="dashed" icon={<PlusOutlined />} onClick={() => add({ field: 'raw', op: 'contains', value: '' })} block>
              添加条件
            </Button>
          </Space>
        )}
      </Form.List>
    </>
  );
}

/** 渲染规则新增/编辑弹窗。 */
export default function RuleEditModal({ open, initial, onClose, onSaved }: RuleEditModalProps) {
  const [form] = Form.useForm<RuleFormValues>();
  const [submitting, setSubmitting] = useState(false);
  const ruleType = Form.useWatch('type', form);

  const isEdit = useMemo(() => Boolean(initial), [initial]);

  useEffect(() => {
    if (!open) {
      return;
    }
    if (initial) {
      form.setFieldsValue({
        id: initial.id,
        name: initial.name,
        description: initial.description ?? '',
        enabled: initial.enabled,
        severity: initial.severity,
        type: initial.type,
        log_types: initial.log_types?.length ? initial.log_types : ['any'],
        tags: initial.tags ?? [],
        all_of: flattenConditions(initial.all_of),
        any_of: flattenConditions(initial.any_of),
        threshold_count: initial.threshold?.count,
        threshold_window: initial.threshold?.window,
        threshold_groupby: initial.threshold?.group_by ?? ['src_ip'],
        first_seen_field: initial.first_seen_field ?? 'src_ip',
        first_seen_lookback: initial.first_seen_lookback ?? 2592000,
        sup_cooldown: initial.suppression?.cooldown ?? undefined,
        sup_ignore_internal: initial.suppression?.ignore_internal ?? false,
        sup_ignore_ips: initial.suppression?.ignore_ips ?? [],
      });
    } else {
      form.resetFields();
      form.setFieldsValue({
        enabled: true,
        severity: 'medium',
        type: 'match',
        log_types: ['any'],
        tags: [],
        all_of: [{ field: 'raw', op: 'contains', value: '' }],
        any_of: [],
        threshold_count: 5,
        threshold_window: 300,
        threshold_groupby: ['src_ip'],
        first_seen_field: 'src_ip',
        first_seen_lookback: 2592000,
        sup_ignore_internal: false,
        sup_ignore_ips: [],
      });
    }
  }, [open, initial, form]);

  /** 组装规则载荷并提交到后端。 */
  const handleOk = async () => {
    const values = await form.validateFields();
    const allOf = buildConditions(values.all_of);
    const anyOf = buildConditions(values.any_of);
    if (allOf.length === 0 && anyOf.length === 0) {
      message.error('请至少配置一个匹配条件（all_of 或 any_of）');
      return;
    }

    const payload = {
      id: values.id.trim(),
      name: values.name.trim(),
      description: values.description?.trim() ?? '',
      enabled: values.enabled,
      severity: values.severity,
      type: values.type,
      log_types: values.log_types?.length ? values.log_types : ['any'],
      tags: values.tags ?? [],
      all_of: allOf,
      any_of: anyOf,
      threshold:
        values.type === 'threshold'
          ? {
              count: values.threshold_count ?? 5,
              window: values.threshold_window ?? 300,
              group_by: values.threshold_groupby?.length ? values.threshold_groupby : ['src_ip'],
            }
          : null,
      first_seen_field: values.first_seen_field?.trim() || 'src_ip',
      first_seen_lookback: values.first_seen_lookback ?? 2592000,
      suppression: {
        cooldown: values.sup_cooldown ?? null,
        ignore_ips: values.sup_ignore_ips ?? [],
        ignore_internal: values.sup_ignore_internal ?? false,
      },
    } as unknown as Rule;

    setSubmitting(true);
    try {
      if (isEdit && initial) {
        await replaceRule(initial.id, payload);
        message.success(`规则「${payload.name}」已更新`);
      } else {
        await createRule(payload);
        message.success(`规则「${payload.name}」已创建并生效`);
      }
      onSaved();
      onClose();
    } catch {
      // 错误提示由 axios 拦截器统一处理
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      title={isEdit ? '编辑自定义规则' : '新增自定义规则'}
      open={open}
      width={860}
      onCancel={onClose}
      onOk={handleOk}
      confirmLoading={submitting}
      okText="保存"
      cancelText="取消"
      destroyOnClose
      maskClosable={false}
    >
      <Form form={form} layout="vertical" style={{ marginTop: 8 }}>
        <Space wrap size={16}>
          <Form.Item
            name="id"
            label="规则 ID"
            rules={[
              { required: true, message: '请输入规则 ID' },
              { pattern: /^[a-z0-9][a-z0-9_-]{1,63}$/, message: '2~64 位小写字母、数字、中划线或下划线' },
            ]}
          >
            <Input placeholder="如 ssh-brute-force" disabled={isEdit} style={{ width: 240 }} />
          </Form.Item>
          <Form.Item name="name" label="规则名称" rules={[{ required: true, message: '请输入规则名称' }]}>
            <Input placeholder="如 SSH 暴力破解" style={{ width: 300 }} />
          </Form.Item>
          <Form.Item name="severity" label="严重等级" rules={[{ required: true }]}>
            <Select options={SEVERITY_OPTIONS} style={{ width: 120 }} />
          </Form.Item>
          <Form.Item name="type" label="规则类型" rules={[{ required: true }]}>
            <Select options={TYPE_OPTIONS} style={{ width: 220 }} />
          </Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked">
            <Switch checkedChildren="启用" unCheckedChildren="停用" />
          </Form.Item>
        </Space>

        <Form.Item name="description" label="规则描述">
          <Input.TextArea rows={2} placeholder="规则检测的行为与处置建议" />
        </Form.Item>

        <Space wrap size={16}>
          <Form.Item name="log_types" label="适用日志类型" style={{ minWidth: 300 }}>
            <Select mode="tags" options={LOG_TYPE_OPTIONS} placeholder="any 表示全部日志" />
          </Form.Item>
          <Form.Item name="tags" label="标签">
            <Select mode="tags" placeholder="如 attack、brute-force" style={{ width: 300 }} />
          </Form.Item>
        </Space>

        <ConditionList name="all_of" label="all_of 条件（全部满足）" hint="列表中的每个条件需同时成立，字段可输入或从常用字段中选择。" />
        <ConditionList name="any_of" label="any_of 条件（任一满足）" hint="列表中的任意一个条件成立即可，与 all_of 为 AND 关系。" />

        {ruleType === 'threshold' ? (
          <>
            <Divider orientation="left" style={{ margin: '12px 0 8px' }}>
              阈值配置
            </Divider>
            <Space wrap size={16}>
              <Form.Item name="threshold_count" label="窗口内次数">
                <InputNumber min={1} style={{ width: 140 }} />
              </Form.Item>
              <Form.Item name="threshold_window" label="统计窗口（秒）">
                <InputNumber min={10} style={{ width: 160 }} />
              </Form.Item>
              <Form.Item name="threshold_groupby" label="分组字段">
                <Select mode="tags" style={{ width: 260 }} placeholder="如 src_ip" />
              </Form.Item>
            </Space>
          </>
        ) : null}

        {ruleType === 'first_seen' ? (
          <>
            <Divider orientation="left" style={{ margin: '12px 0 8px' }}>
              首次出现配置
            </Divider>
            <Space wrap size={16}>
              <Form.Item name="first_seen_field" label="观测字段">
                <Input style={{ width: 220 }} placeholder="如 src_ip" />
              </Form.Item>
              <Form.Item name="first_seen_lookback" label="回溯时长（秒）">
                <InputNumber min={60} style={{ width: 200 }} />
              </Form.Item>
            </Space>
          </>
        ) : null}

        <Divider orientation="left" style={{ margin: '12px 0 8px' }}>
          降噪配置 suppression
        </Divider>
        <Space wrap size={16}>
          <Form.Item name="sup_cooldown" label="冷却时间（秒，留空用全局值）">
            <InputNumber min={0} style={{ width: 220 }} placeholder="如 1800" />
          </Form.Item>
          <Form.Item name="sup_ignore_ips" label="忽略的源 IP 列表">
            <Select mode="tags" style={{ width: 280 }} placeholder="输入 IP 后回车" />
          </Form.Item>
          <Form.Item name="sup_ignore_internal" label="忽略内网地址" valuePropName="checked">
            <Switch checkedChildren="忽略" unCheckedChildren="检测" />
          </Form.Item>
        </Space>
      </Form>
    </Modal>
  );
}
