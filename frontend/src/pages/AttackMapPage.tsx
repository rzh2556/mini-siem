/** 攻击地图页面：世界地图打点展示攻击来源，右侧面板可点击定位到地图。 */
import { useCallback, useEffect, useState } from 'react';
import { Card, Col, List, Row, Segmented, Spin, Tag, Typography } from 'antd';
import { fetchGeo } from '../api/endpoints';
import type { GeoAttacker } from '../api/types';
import AttackMap from '../components/AttackMap';
import SeverityTag from '../components/SeverityTag';
import { formatNumber, formatTime } from '../utils/format';

/** 可选时间范围 */
const RANGE_OPTIONS = [
  { label: '最近 24 小时', value: 24 },
  { label: '最近 72 小时', value: 72 },
  { label: '最近 7 天', value: 168 },
];

/** 渲染攻击地图页面。 */
export default function AttackMapPage() {
  const [hours, setHours] = useState(72);
  const [attackers, setAttackers] = useState<GeoAttacker[]>([]);
  const [total, setTotal] = useState(0);
  const [updatedAt, setUpdatedAt] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [focusIp, setFocusIp] = useState<string | null>(null);
  const [mapHeight, setMapHeight] = useState(620);

  /** 加载攻击地图数据 */
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchGeo(hours);
      setAttackers(data.attackers);
      setTotal(data.total);
      setUpdatedAt(data.updated_at);
    } catch {
      // 错误提示已由 axios 拦截器统一处理
    } finally {
      setLoading(false);
    }
  }, [hours]);

  useEffect(() => {
    load();
  }, [load]);

  // 根据窗口高度自适应地图高度，保证地图占据主要可视区域
  useEffect(() => {
    const updateHeight = () => setMapHeight(Math.max(420, window.innerHeight - 250));
    updateHeight();
    window.addEventListener('resize', updateHeight);
    return () => window.removeEventListener('resize', updateHeight);
  }, []);

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">攻击地图</h2>
          <div className="page-subtitle">
            共 {attackers.length} 个攻击源，攻击次数合计 {formatNumber(total)} 次 · 数据更新于{' '}
            {formatTime(updatedAt)}
          </div>
        </div>
        <div className="page-toolbar">
          <Segmented value={hours} options={RANGE_OPTIONS} onChange={(value) => setHours(Number(value))} />
        </div>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={18}>
          <Card bodyStyle={{ padding: 12 }}>
            <Spin spinning={loading}>
              <AttackMap
                attackers={attackers}
                height={mapHeight}
                focusIp={focusIp}
                onSelect={setFocusIp}
              />
            </Spin>
          </Card>
        </Col>
        <Col xs={24} xl={6}>
          <Card
            title={<span className="card-title">TOP 攻击源</span>}
            bodyStyle={{ padding: 0, maxHeight: mapHeight + 24, overflowY: 'auto' }}
          >
            <List
              size="small"
              dataSource={attackers}
              locale={{ emptyText: '暂无攻击源数据' }}
              renderItem={(item, index) => (
                <List.Item
                  key={item.src_ip}
                  onClick={() => setFocusIp(item.src_ip)}
                  style={{
                    cursor: 'pointer',
                    padding: '10px 14px',
                    background: focusIp === item.src_ip ? 'rgba(23,125,220,0.16)' : undefined,
                  }}
                >
                  <div style={{ width: '100%' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Tag color={index < 3 ? 'red' : 'default'} style={{ marginInlineEnd: 0 }}>
                        #{index + 1}
                      </Tag>
                      <Typography.Text strong style={{ flex: 1 }}>
                        {item.src_ip}
                      </Typography.Text>
                      <SeverityTag severity={item.severity} />
                    </div>
                    <div className="page-subtitle" style={{ marginTop: 4 }}>
                      攻击 {formatNumber(item.count)} 次 ·{' '}
                      {[item.country, item.city].filter(Boolean).join(' / ') || '归属地未知'}
                    </div>
                    <div className="page-subtitle">
                      最近 {formatTime(item.last_seen)}
                      {item.hosts.length > 0 ? ` · 目标 ${item.hosts.slice(0, 3).join('、')}` : ''}
                    </div>
                  </div>
                </List.Item>
              )}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
