/** 严重等级展示：统一的颜色与中文文案映射，供标签与图表共用。 */
import { Tag } from 'antd';
import type { Severity } from '../api/types';

/** 严重等级 -> 中文文案 */
export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
};

/** 严重等级 -> 展示颜色 */
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#cf1322',
  high: '#fa541c',
  medium: '#faad14',
  low: '#52c41a',
};

/** 严重等级权重，用于比较高低（数值越大越严重） */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/** 判断字符串是否为合法的严重等级 */
export function isSeverity(value?: string | null): value is Severity {
  return value === 'critical' || value === 'high' || value === 'medium' || value === 'low';
}

/** 严重等级标签组件属性 */
interface SeverityTagProps {
  /** 后端返回的等级值 */
  severity?: Severity | string | null;
}

/** 渲染中文严重等级标签，未知等级按原值展示。 */
export default function SeverityTag({ severity }: SeverityTagProps) {
  if (severity && isSeverity(severity)) {
    return <Tag color={SEVERITY_COLORS[severity]}>{SEVERITY_LABELS[severity]}</Tag>;
  }
  return <Tag>{severity || '-'}</Tag>;
}
