/** 全局类型定义：与后端 /api/v1 的响应结构保持一一对应。 */

/** 告警严重等级 */
export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** 告警处理状态 */
export type AlertStatus = 'open' | 'acknowledged' | 'closed';

/** 日志来源类型 */
export type SourceType = 'nginx' | 'apache' | 'ssh' | 'windows' | 'syslog' | 'linux' | 'unknown';

/** 规则类型 */
export type RuleType = 'match' | 'threshold' | 'first_seen';

/** 健康检查响应 */
export interface HealthResponse {
  status: 'ok' | 'degraded';
  version: string;
  elasticsearch: boolean;
  rules_loaded: number;
  rules_enabled: number;
}

/** 名称 + 数量 的通用聚合项 */
export interface NameCount {
  name: string;
  count: number;
}

/** 国家 + 数量 的聚合项 */
export interface CountryCount {
  country_code: string;
  count: number;
}

/** TOP 攻击源 IP 聚合项 */
export interface TopSrcIp {
  src_ip: string;
  count: number;
  country_code?: string | null;
  severity?: Severity | null;
}

/** 告警等级分布 */
export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** 仪表盘总览响应 */
export interface OverviewResponse {
  hours: number;
  logs_total: number;
  alerts_total: number;
  open_alerts: number;
  severity_distribution: SeverityDistribution;
  top_rules: NameCount[];
  status_distribution: Partial<Record<AlertStatus, number>>;
  top_src_ips: TopSrcIp[];
  top_countries: CountryCount[];
  source_types: NameCount[];
  hosts: NameCount[];
}

/** 时间趋势中的单个数据点 */
export interface TimelinePoint {
  time: string;
  logs: number;
  alerts: number;
}

/** 时间趋势响应 */
export interface TimelineResponse {
  interval: string;
  points: TimelinePoint[];
}

/** IP 地理位置信息 */
export interface GeoInfo {
  country?: string | null;
  country_code?: string | null;
  city?: string | null;
  lat?: number | null;
  lon?: number | null;
}

/** 攻击地图上的一个攻击源 */
export interface GeoAttacker {
  src_ip: string;
  country?: string | null;
  country_code?: string | null;
  city?: string | null;
  lat?: number | null;
  lon?: number | null;
  count: number;
  severity: Severity;
  rules: string[];
  last_seen?: string | null;
  hosts: string[];
}

/** 攻击地图响应 */
export interface GeoResponse {
  total: number;
  attackers: GeoAttacker[];
  updated_at: string;
}

/** 攻击源排行榜条目 */
export interface AttackerItem {
  src_ip: string;
  count: number;
  hosts: string[];
  rules: string[];
  country_code?: string | null;
  severity?: Severity | null;
  last_seen?: string | null;
}

/** 攻击源排行榜响应 */
export interface AttackersResponse {
  hours: number;
  items: AttackerItem[];
}

/** 告警关联的原始日志样本 */
export interface AlertSample {
  timestamp: string;
  host?: string | null;
  src_ip?: string | null;
  raw: string;
}

/** 告警实体 */
export interface Alert {
  id?: string | null;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  status: AlertStatus;
  first_seen: string;
  last_seen: string;
  count: number;
  group_key?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  host?: string | null;
  user?: string | null;
  description?: string | null;
  tags?: string[] | null;
  samples?: AlertSample[] | null;
  geo?: GeoInfo | null;
  ack_comment?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

/** 归一化日志事件 */
export interface LogEvent {
  id?: string | null;
  timestamp: string;
  host?: string | null;
  source_type?: SourceType | string | null;
  level?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  user?: string | null;
  method?: string | null;
  url?: string | null;
  path?: string | null;
  query?: string | null;
  status_code?: number | null;
  user_agent?: string | null;
  event_id?: number | null;
  channel?: string | null;
  process?: string | null;
  command?: string | null;
  message?: string | null;
  raw?: string | null;
  tags?: string[] | null;
  matched_rules?: string[] | null;
  geo?: GeoInfo | null;
}

/** 通用分页响应 */
export interface PageResult<T> {
  total: number;
  items: T[];
}

/** 日志检索筛选项 */
export interface LogFilters {
  source_types: string[];
  hosts: string[];
  levels: string[];
}

/** 规则匹配条件 */
export interface RuleCondition {
  field: string;
  regex?: string | null;
  equals?: unknown;
  contains?: string | null;
  in?: unknown[] | null;
  not_in?: unknown[] | null;
  gt?: number | null;
  lt?: number | null;
}

/** 阈值规则配置 */
export interface ThresholdConfig {
  count: number;
  window: number;
  group_by: string[];
}

/** 时间窗条件配置 */
export interface TimeWindowConfig {
  start: string;
  end: string;
  mode: 'inside' | 'outside';
}

/** 降噪配置 */
export interface SuppressionConfig {
  cooldown?: number | null;
  ignore_ips?: string[];
  ignore_internal?: boolean;
}

/** 检测规则 */
export interface Rule {
  id: string;
  name: string;
  description?: string | null;
  severity: Severity;
  type: RuleType;
  enabled: boolean;
  log_types: string[];
  tags: string[];
  all_of: RuleCondition[];
  any_of: RuleCondition[];
  time_window?: TimeWindowConfig | null;
  threshold?: ThresholdConfig | null;
  first_seen_field?: string | null;
  first_seen_lookback?: number | null;
  suppression?: SuppressionConfig | null;
  enabled_source?: string | null;
}

/** 规则列表响应 */
export interface RulesResponse {
  total: number;
  enabled: number;
  items: Rule[];
}

/** 规则在线调整入参 */
export interface RuleUpdatePayload {
  enabled?: boolean;
  severity?: Severity;
  threshold?: ThresholdConfig;
}

/** 告警列表查询参数 */
export interface AlertQuery {
  status?: AlertStatus | string;
  severity?: Severity | string;
  rule_id?: string;
  src_ip?: string;
  host?: string;
  user?: string;
  keyword?: string;
  from?: string;
  to?: string;
  page?: number;
  size?: number;
}

/** 日志文件上传后的解析结果预览条目 */
export interface UploadPreviewItem {
  /** 事件时间（ISO 字符串） */
  timestamp?: string;
  /** 源 IP */
  src_ip?: string | null;
  /** 关联用户 */
  user?: string | null;
  /** 日志等级 */
  level?: string;
  /** 日志摘要 */
  message?: string;
  /** 命中的规则 ID 列表 */
  matched?: string[];
}

/** 日志文件上传解析结果 */
export interface UploadResult {
  /** 上传的文件名 */
  filename: string;
  /** 后端解析出的日志类型 */
  source_type: string;
  /** 是否由后端自动识别日志类型 */
  auto_detected: boolean;
  /** 文件总行数 */
  total_lines: number;
  /** 成功解析入库的条数 */
  accepted: number;
  /** 跳过的条数（空行、超限、解析失败等） */
  skipped: number;
  /** 本次新产生的告警数 */
  alerts: number;
  /** 前若干条解析结果预览 */
  preview: UploadPreviewItem[];
}

/** 日志检索参数 */
export interface LogQuery {
  q?: string;
  source_type?: string;
  host?: string;
  src_ip?: string;
  user?: string;
  level?: string;
  status_code?: number | string;
  matched_rule?: string;
  from?: string;
  to?: string;
  sort?: string;
  order?: 'asc' | 'desc';
  page?: number;
  size?: number;
}
