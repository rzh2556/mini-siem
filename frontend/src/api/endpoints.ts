/** 后端 API 调用封装：按业务域组织，返回强类型结果。 */
import client from './client';
import type {
  Alert,
  AlertQuery,
  AlertStatus,
  AttackersResponse,
  CurrentUser,
  DeleteResult,
  EditableSettings,
  GeoResponse,
  HealthResponse,
  LoginRequest,
  LoginResponse,
  LogEvent,
  LogFilters,
  LogQuery,
  OverviewResponse,
  PageResult,
  Rule,
  RulesResponse,
  RuleSavePayload,
  RuleUpdatePayload,
  SigmaImportResponse,
  SettingsResponse,
  SettingsSaveResponse,
  SystemInfo,
  TimelineResponse,
  UploadBatchList,
  UploadResult,
} from './types';

/** 过滤空值参数，避免把空字符串或 undefined 传给后端。 */
function cleanParams(params: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      result[key] = value;
    }
  });
  return result;
}

/** 健康检查：返回服务与 Elasticsearch 状态。 */
export async function fetchHealth(): Promise<HealthResponse> {
  const { data } = await client.get<HealthResponse>('/health');
  return data;
}

/** 仪表盘总览指标：指标卡与各类 TOP 排行。 */
export async function fetchOverview(hours: number): Promise<OverviewResponse> {
  const { data } = await client.get<OverviewResponse>('/stats/overview', {
    params: { hours },
  });
  return data;
}

/** 日志/告警时间趋势：按指定间隔分桶。 */
export async function fetchTimeline(hours: number, interval: string): Promise<TimelineResponse> {
  const { data } = await client.get<TimelineResponse>('/stats/timeline', {
    params: { hours, interval },
  });
  return data;
}

/** 攻击地图数据：返回带经纬度的攻击源汇总。 */
export async function fetchGeo(hours: number, limit?: number): Promise<GeoResponse> {
  const { data } = await client.get<GeoResponse>('/stats/geo', {
    params: cleanParams({ hours, limit }),
  });
  return data;
}

/** 攻击源排行榜：返回攻击次数排名与命中规则、被攻击主机。 */
export async function fetchAttackers(hours: number, limit = 20): Promise<AttackersResponse> {
  const { data } = await client.get<AttackersResponse>('/stats/attackers', {
    params: { hours, limit },
  });
  return data;
}

/** 分页查询告警列表。 */
export async function fetchAlerts(params: AlertQuery): Promise<PageResult<Alert>> {
  const { data } = await client.get<PageResult<Alert>>('/alerts', {
    params: cleanParams(params as Record<string, unknown>),
  });
  return data;
}

/** 查询单条告警详情（含原始日志样本）。 */
export async function fetchAlertDetail(id: string): Promise<Alert> {
  const { data } = await client.get<Alert>(`/alerts/${id}`);
  return data;
}

/** 更新单条告警的状态与备注。 */
export async function updateAlert(
  id: string,
  payload: { status?: AlertStatus; comment?: string },
): Promise<Alert> {
  const { data } = await client.patch<Alert>(`/alerts/${id}`, payload);
  return data;
}

/** 批量更新告警状态，返回被更新条数。 */
export async function bulkUpdateAlerts(
  ids: string[],
  status: AlertStatus,
): Promise<{ updated: number }> {
  const { data } = await client.post<{ updated: number }>('/alerts/bulk', { ids, status });
  return data;
}

/** 检索归一化日志，返回服务端分页结果。 */
export async function searchLogs(params: LogQuery): Promise<PageResult<LogEvent>> {
  const { data } = await client.get<PageResult<LogEvent>>('/logs/search', {
    params: cleanParams(params as Record<string, unknown>),
  });
  return data;
}

/** 获取日志检索可用的筛选值（来源类型、主机、等级）。 */
export async function fetchLogFilters(hours = 24): Promise<LogFilters> {
  const { data } = await client.get<LogFilters>('/logs/filters', { params: { hours } });
  return data;
}

/** 分页查询日志文件上传批次列表（用于按批次管理/删除）。 */
export async function listUploadBatches(page = 1, size = 20): Promise<UploadBatchList> {
  const { data } = await client.get<UploadBatchList>('/logs/uploads', { params: { page, size } });
  return data;
}

/** 删除某次上传文件产生的整批日志。 */
export async function deleteUploadBatch(batchId: string): Promise<DeleteResult> {
  const { data } = await client.delete<DeleteResult>(`/logs/uploads/${batchId}`);
  return data;
}

/** 删除单条日志（按日志 ID）。 */
export async function deleteLog(logId: string): Promise<DeleteResult> {
  const { data } = await client.delete<DeleteResult>(`/logs/${logId}`);
  return data;
}

/** 批量删除日志（按日志 ID 列表）。 */
export async function bulkDeleteLogs(ids: string[]): Promise<DeleteResult> {
  const { data } = await client.post<DeleteResult>('/logs/delete', { ids });
  return data;
}

/** 清空全部日志（含上传批次记录，不影响告警）。 */
export async function purgeLogs(): Promise<DeleteResult> {
  const { data } = await client.post<DeleteResult>('/logs/purge');
  return data;
}

/** 获取全部检测规则及启停状态。 */
export async function fetchRules(): Promise<RulesResponse> {
  const { data } = await client.get<RulesResponse>('/rules');
  return data;
}

/** 在线调整规则（启停、等级、阈值）。 */
export async function updateRule(id: string, payload: RuleUpdatePayload): Promise<Rule> {
  const { data } = await client.patch<Rule>(`/rules/${id}`, payload);
  return data;
}

/** 触发后端重新加载规则文件，返回加载条数。 */
export async function reloadRules(): Promise<{ loaded: number }> {
  const { data } = await client.post<{ loaded: number }>('/rules/reload');
  return data;
}

/** 新增一条自定义规则。 */
export async function createRule(payload: RuleSavePayload): Promise<Rule> {
  const { data } = await client.post<Rule>('/rules', payload);
  return data;
}

/** 整体更新一条自定义规则。 */
export async function replaceRule(id: string, payload: RuleSavePayload): Promise<Rule> {
  const { data } = await client.put<Rule>(`/rules/${id}`, payload);
  return data;
}

/** 删除一条自定义规则。 */
export async function removeRule(id: string): Promise<{ deleted: boolean }> {
  const { data } = await client.delete<{ deleted: boolean }>(`/rules/${id}`);
  return data;
}

/**
 * 导入 Sigma 规则 YAML（支持 --- 分隔多条文档）。
 * @param content Sigma YAML 文本
 * @param overwrite 已存在的同 ID 自定义规则是否覆盖更新
 */
export async function importSigmaRules(
  content: string,
  overwrite: boolean,
): Promise<SigmaImportResponse> {
  const { data } = await client.post<SigmaImportResponse>('/rules/import-sigma', {
    content,
    overwrite,
  });
  return data;
}

/** 管理员登录，返回 JWT 与账号信息。 */
export async function login(payload: LoginRequest): Promise<LoginResponse> {
  const { data } = await client.post<LoginResponse>('/auth/login', payload);
  return data;
}

/** 查询当前登录用户，用于校验本地令牌是否仍有效。 */
export async function fetchMe(): Promise<CurrentUser> {
  const { data } = await client.get<CurrentUser>('/auth/me');
  return data;
}

/** 修改当前账号密码。 */
export async function changePassword(payload: {
  old_password: string;
  new_password: string;
}): Promise<{ message: string }> {
  const { data } = await client.post<{ message: string }>('/auth/change-password', payload);
  return data;
}

/** 获取系统运行参数。 */
export async function fetchSettings(): Promise<SettingsResponse> {
  const { data } = await client.get<SettingsResponse>('/admin/settings');
  return data;
}

/** 保存系统运行参数（仅提交变化项）。 */
export async function saveSettings(
  payload: Partial<EditableSettings>,
): Promise<SettingsSaveResponse> {
  const { data } = await client.put<SettingsSaveResponse>('/admin/settings', payload);
  return data;
}

/** 重新生成 Agent 采集令牌。 */
export async function regenerateAgentToken(): Promise<{ agent_token: string; message: string }> {
  const { data } = await client.post<{ agent_token: string; message: string }>(
    '/admin/agent-token/regenerate',
  );
  return data;
}

/** 获取系统信息。 */
export async function fetchSystemInfo(): Promise<SystemInfo> {
  const { data } = await client.get<SystemInfo>('/admin/system');
  return data;
}

/**
 * 上传单个日志文件并解析入库。
 * @param file 待上传的日志文件
 * @param host 日志来源主机名，留空由后端使用默认值
 * @param sourceType 日志类型，auto 表示由后端自动识别
 * @param onProgress 可选的上传进度回调，参数为 0-100 的百分比
 */
export async function uploadLogFile(
  file: File,
  host: string,
  sourceType: string,
  onProgress?: (percent: number) => void,
): Promise<UploadResult> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('host', host);
  formData.append('source_type', sourceType);
  // 不手动设置 Content-Type，交给浏览器自动补全 multipart 的 boundary
  // 大 EVTX 文件解析较慢，单独放宽超时到 10 分钟（全局默认仅 30 秒）
  const { data } = await client.post<UploadResult>('/ingest/upload', formData, {
    timeout: 600000,
    onUploadProgress: (event) => {
      if (!onProgress || !event.total) {
        return;
      }
      onProgress(Math.round((event.loaded / event.total) * 100));
    },
  });
  return data;
}
