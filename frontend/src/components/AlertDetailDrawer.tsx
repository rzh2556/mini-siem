/** 告警详情抽屉：展示告警全部字段、原始日志样本与地理位置，并支持状态流转。 */
import { useState } from 'react';
import { Button, Descriptions, Divider, Drawer, Empty, List, Space, Tag, Typography, message } from 'antd';
import { updateAlert } from '../api/endpoints';
import type { Alert, AlertStatus } from '../api/types';
import { formatTime } from '../utils/format';
import SeverityTag from './SeverityTag';

/** 告警状态 -> 中文文案 */
export const STATUS_LABELS: Record<AlertStatus, string> = {
  open: '未处理',
  acknowledged: '已处理',
  closed: '已关闭',
};

/** 告警状态 -> 标签颜色 */
export const STATUS_COLORS: Record<AlertStatus, string> = {
  open: 'red',
  acknowledged: 'gold',
  closed: 'default',
};

/** 抽屉属性 */
interface AlertDetailDrawerProps {
  /** 是否可见 */
  open: boolean;
  /** 当前展示的告警 */
  alert: Alert | null;
  /** 详情加载中 */
  loading?: boolean;
  /** 关闭回调 */
  onClose: () => void;
  /** 状态更新成功后的回调（用于刷新列表） */
  onUpdated: () => void;
}

/** 渲染告警详情抽屉。 */
export default function AlertDetailDrawer({
  open,
  alert,
  loading,
  onClose,
  onUpdated,
}: AlertDetailDrawerProps) {
  const [submitting, setSubmitting] = useState(false);

  /** 变更告警状态并提示结果 */
  const changeStatus = (status: AlertStatus, comment?: string) => {
    if (!alert?.id) {
      return;
    }
    setSubmitting(true);
    updateAlert(alert.id, { status, comment })
      .then(() => {
        message.success(`告警已${comment ? '更新备注并' : ''}标记为${STATUS_LABELS[status]}`);
        onUpdated();
      })
      .catch(() => undefined)
      .finally(() => setSubmitting(false));
  };

  /** 渲染状态操作按钮 */
  const renderActions = () => {
    if (!alert) {
      return null;
    }
    return (
      <Space>
        <Button
          type="primary"
          size="small"
          loading={submitting}
          disabled={alert.status === 'acknowledged'}
          onClick={() => changeStatus('acknowledged', '已确认')}
        >
          标记已处理
        </Button>
        <Button
          size="small"
          loading={submitting}
          disabled={alert.status === 'closed'}
          onClick={() => changeStatus('closed', '已关闭')}
        >
          关闭告警
        </Button>
      </Space>
    );
  };

  return (
    <Drawer
      title={alert ? `告警详情：${alert.rule_name}` : '告警详情'}
      width={720}
      open={open}
      onClose={onClose}
      destroyOnClose
      extra={renderActions()}
    >
      {alert ? (
        <>
          <Descriptions column={2} size="small" bordered>
            <Descriptions.Item label="告警 ID" span={2}>
              <Typography.Text copyable>{alert.id || '-'}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="严重等级">
              <SeverityTag severity={alert.severity} />
            </Descriptions.Item>
            <Descriptions.Item label="处理状态">
              <Tag color={STATUS_COLORS[alert.status]}>{STATUS_LABELS[alert.status]}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="规则 ID">{alert.rule_id}</Descriptions.Item>
            <Descriptions.Item label="关联次数">{alert.count}</Descriptions.Item>
            <Descriptions.Item label="源 IP">{alert.src_ip || '-'}</Descriptions.Item>
            <Descriptions.Item label="目标 IP">{alert.dst_ip || '-'}</Descriptions.Item>
            <Descriptions.Item label="受影响主机">{alert.host || '-'}</Descriptions.Item>
            <Descriptions.Item label="关联用户">{alert.user || '-'}</Descriptions.Item>
            <Descriptions.Item label="首次发现">{formatTime(alert.first_seen)}</Descriptions.Item>
            <Descriptions.Item label="最近发现">{formatTime(alert.last_seen)}</Descriptions.Item>
            <Descriptions.Item label="创建时间">{formatTime(alert.created_at)}</Descriptions.Item>
            <Descriptions.Item label="更新时间">{formatTime(alert.updated_at)}</Descriptions.Item>
            <Descriptions.Item label="分组标识" span={2}>
              {alert.group_key || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="地理位置" span={2}>
              {alert.geo
                ? [alert.geo.country, alert.geo.country_code, alert.geo.city].filter(Boolean).join(' / ') ||
                  '未知'
                : '无地理位置数据'}
              {alert.geo?.lat != null && alert.geo?.lon != null
                ? `（${alert.geo.lat}, ${alert.geo.lon}）`
                : ''}
            </Descriptions.Item>
            <Descriptions.Item label="处理备注" span={2}>
              {alert.ack_comment || '-'}
            </Descriptions.Item>
          </Descriptions>

          <Divider orientation="left">告警描述</Divider>
          <Typography.Paragraph style={{ marginBottom: 0 }}>
            {alert.description || '无描述'}
          </Typography.Paragraph>

          <Divider orientation="left">标签</Divider>
          {alert.tags && alert.tags.length > 0 ? (
            alert.tags.map((tag) => (
              <Tag key={tag} color="blue">
                {tag}
              </Tag>
            ))
          ) : (
            <Typography.Text type="secondary">无标签</Typography.Text>
          )}

          <Divider orientation="left">原始日志样本</Divider>
          {alert.samples && alert.samples.length > 0 ? (
            <List
              size="small"
              dataSource={alert.samples}
              renderItem={(sample, index) => (
                <List.Item key={`${sample.timestamp}-${index}`} className="sample-item">
                  <div className="sample-item__meta">
                    <span>时间：{formatTime(sample.timestamp)}</span>
                    <span>主机：{sample.host || '-'}</span>
                    <span>源 IP：{sample.src_ip || '-'}</span>
                  </div>
                  <pre className="raw-block">{sample.raw || '（无原始内容）'}</pre>
                </List.Item>
              )}
            />
          ) : (
            <Empty description="暂无原始日志样本" />
          )}
        </>
      ) : (
        <Empty description={loading ? '加载中' : '暂无告警数据'} />
      )}
    </Drawer>
  );
}
