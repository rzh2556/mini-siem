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
  /** 当前使用的存储后端：sqlite / elasticsearch */
  backend: string;
  /** 存储后端是否可用 */
  storage: boolean;
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
  /** 所属上传批次号（文件上传时写入，Agent 直报为空） */
  batch_id?: string | null;
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
  /** 不包含子串（大小写不敏感） */
  not_contains?: string | null;
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
  /** 是否为后台新增的自定义规则（内置规则不可删除/整体修改） */
  managed?: boolean;
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

/** 规则创建/整体更新入参与规则实体一致（managed 等运行期字段由后端忽略） */
export type RuleSavePayload = Rule;

/** 单条 Sigma 文档的导入结果 */
export interface SigmaImportItem {
  title: string;
  sigma_id?: string | null;
  rule_ids?: string[] | null;
  severity?: string | null;
  /** imported 已导入 / skipped 跳过（重复或内置冲突）/ error 转换失败 */
  status: 'imported' | 'skipped' | 'error';
  warnings?: string[] | null;
  error?: string | null;
}

/** Sigma 规则导入汇总结果 */
export interface SigmaImportResponse {
  imported: number;
  skipped: number;
  failed: number;
  items: SigmaImportItem[];
}

/** 管理员登录入参 */
export interface LoginRequest {
  username: string;
  password: string;
}

/** 登录成功响应 */
export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_at: string;
  username: string;
  /** 是否必须先修改默认密码 */
  must_change_password: boolean;
}

/** 当前登录用户 */
export interface CurrentUser {
  username: string;
}

/** 后台可编辑的运行参数 */
export interface EditableSettings {
  es_retention_days: number;
  alert_cooldown: number;
  min_alert_severity: Severity;
  ip_whitelist: string;
  ignore_internal_src: boolean;
  geoip_online_fallback: boolean;
  geoip_db_path: string;
  log_level: string;
  cors_origins: string;
  api_token: string;
  agent_token: string;
  rules_reload_interval: number;
  /** 单文件上传大小上限（MB） */
  max_upload_mb: number;
  /** 单文件最多解析的日志条数 */
  max_upload_lines: number;
}

/** 只读部署参数 */
export interface ReadOnlySettings {
  storage_backend: string;
  sqlite_path: string;
  es_url: string;
  frontend_dist: string;
  rules_dir: string;
  system_db_path: string;
  admin_username: string;
  token_expire_hours: number;
}

/** 系统设置查询响应 */
export interface SettingsResponse {
  editable: EditableSettings;
  read_only: ReadOnlySettings;
  restart_required_keys: string[];
}

/** 系统设置保存响应 */
export interface SettingsSaveResponse {
  message: string;
  restart_required: boolean;
  editable: EditableSettings;
}

/** 系统信息 */
export interface SystemInfo {
  version: string;
  hostname: string;
  platform: string;
  python: string;
  backend: string;
  storage_ok: boolean;
  rules_loaded: number;
  rules_enabled: number;
  uptime_seconds: number;
  business_db_bytes: number;
  system_db_bytes: number;
  server_time: string;
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
  /** 本次上传的批次号，可用于按批次删除该批日志 */
  batch_id: string;
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

/** 上传批次条目（按文件批次管理，用于展示与删除本批日志） */
export interface UploadBatchItem {
  batch_id: string;
  filename?: string | null;
  host?: string | null;
  source_type?: string | null;
  /** 上传时解析出的总行数 */
  total: number;
  /** 上传时成功入库条数 */
  accepted: number;
  /** 上传时产生的告警数 */
  alerts: number;
  /** 文件字节大小 */
  size_bytes: number;
  note?: string | null;
  created_at?: string | null;
  /** 当前库中仍存在的该批次日志条数（可能因单条删除而减少） */
  current: number;
}

/** 上传批次分页响应 */
export interface UploadBatchList {
  total: number;
  items: UploadBatchItem[];
}

/** 删除操作结果 */
export interface DeleteResult {
  deleted: number;
  message?: string;
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
