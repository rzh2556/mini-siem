/** 时间格式化工具：把后端返回的 ISO 时间统一转成本地时区展示。 */
import dayjs from 'dayjs';

/** 统一的日期时间展示格式 */
export const DATETIME_FORMAT = 'YYYY-MM-DD HH:mm:ss';

/** 把 ISO 时间字符串格式化为本地时间，空值返回占位符 "-"。 */
export function formatTime(value?: string | number | null): string {
  if (!value) {
    return '-';
  }
  const parsed = dayjs(value);
  return parsed.isValid() ? parsed.format(DATETIME_FORMAT) : '-';
}

/** 把秒数转换为中文可读的时长描述，例如 300 -> "5 分钟"。 */
export function formatSeconds(seconds?: number | null): string {
  if (!seconds || seconds <= 0) {
    return '-';
  }
  if (seconds % 86400 === 0) {
    return `${seconds / 86400} 天`;
  }
  if (seconds % 3600 === 0) {
    return `${seconds / 3600} 小时`;
  }
  if (seconds % 60 === 0) {
    return `${seconds / 60} 分钟`;
  }
  return `${seconds} 秒`;
}

/** 把数字按千分位格式化，便于大数值阅读。 */
export function formatNumber(value?: number | null): string {
  if (value === undefined || value === null) {
    return '0';
  }
  return value.toLocaleString('zh-CN');
}
