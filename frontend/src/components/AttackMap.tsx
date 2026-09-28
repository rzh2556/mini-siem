/** 攻击地图组件：基于 Leaflet + OpenStreetMap 展示攻击源地理分布。 */
import { useEffect, useMemo, useRef } from 'react';
import type { MutableRefObject } from 'react';
import type { CircleMarker as LeafletCircleMarker } from 'leaflet';
import { CircleMarker, MapContainer, Popup, TileLayer, useMap } from 'react-leaflet';
import { Empty } from 'antd';
import 'leaflet/dist/leaflet.css';
import type { GeoAttacker } from '../api/types';
import { formatTime } from '../utils/format';
import SeverityTag, { SEVERITY_COLORS } from './SeverityTag';

/** 攻击地图属性 */
interface AttackMapProps {
  /** 攻击源列表，仅带经纬度的条目会被打点 */
  attackers: GeoAttacker[];
  /** 地图高度（像素） */
  height?: number;
  /** 需要定位并展开弹窗的攻击源 IP */
  focusIp?: string | null;
  /** 点击标记时的回调 */
  onSelect?: (ip: string) => void;
}

/** 根据攻击次数计算标记半径，使用平方根缩放避免极端值过大。 */
function radiusOf(count: number): number {
  return Math.min(28, 5 + Math.sqrt(Math.max(count, 1)) * 2.4);
}

/** 获取某个等级对应的标记颜色，未知等级使用主色。 */
function colorOf(severity: string): string {
  if (severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low') {
    return SEVERITY_COLORS[severity];
  }
  return '#177ddc';
}

/** 地图视野控制器：focusIp 变化时飞向对应标记并自动打开弹窗。 */
function MapFocus({
  markers,
  focusIp,
  markerRefs,
}: {
  markers: GeoAttacker[];
  focusIp?: string | null;
  markerRefs: MutableRefObject<Record<string, LeafletCircleMarker | null>>;
}) {
  const map = useMap();

  useEffect(() => {
    if (!focusIp) {
      return;
    }
    const target = markers.find((item) => item.src_ip === focusIp);
    if (!target || target.lat == null || target.lon == null) {
      return;
    }
    map.flyTo([target.lat, target.lon], Math.max(map.getZoom(), 3), { duration: 0.8 });
    const timer = window.setTimeout(() => {
      markerRefs.current[focusIp]?.openPopup();
    }, 900);
    return () => window.clearTimeout(timer);
  }, [focusIp, markers, map, markerRefs]);

  return null;
}

/** 渲染攻击地图，无坐标数据时展示空状态提示。 */
export default function AttackMap({ attackers, height = 420, focusIp, onSelect }: AttackMapProps) {
  const markerRefs = useRef<Record<string, LeafletCircleMarker | null>>({});

  // 仅保留具备经纬度的攻击源
  const markers = useMemo(
    () => attackers.filter((item) => typeof item.lat === 'number' && typeof item.lon === 'number'),
    [attackers],
  );

  if (markers.length === 0) {
    return (
      <div className="map-empty" style={{ height }}>
        <Empty description="暂无地理位置数据，请在服务端配置 GeoIP 数据库或开启在线解析" />
      </div>
    );
  }

  return (
    <div className="attack-map" style={{ height }}>
      <MapContainer
        center={[20, 0]}
        zoom={2}
        minZoom={2}
        worldCopyJump
        scrollWheelZoom
        style={{ height: '100%', width: '100%' }}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        <MapFocus markers={markers} focusIp={focusIp} markerRefs={markerRefs} />
        {markers.map((item) => (
          <CircleMarker
            key={item.src_ip}
            center={[item.lat as number, item.lon as number]}
            radius={radiusOf(item.count)}
            pathOptions={{
              color: colorOf(item.severity),
              fillColor: colorOf(item.severity),
              fillOpacity: 0.45,
              weight: 2,
            }}
            ref={(instance) => {
              markerRefs.current[item.src_ip] = instance;
            }}
            eventHandlers={{ click: () => onSelect?.(item.src_ip) }}
          >
            <Popup>
              <div className="map-popup">
                <div className="map-popup__title">{item.src_ip}</div>
                <div className="map-popup__row">
                  归属地：{[item.country, item.city].filter(Boolean).join(' / ') || '未知'}
                </div>
                <div className="map-popup__row">攻击次数：{item.count}</div>
                <div className="map-popup__row">
                  最高等级：<SeverityTag severity={item.severity} />
                </div>
                <div className="map-popup__row">
                  命中规则：{item.rules.length ? item.rules.join('、') : '无'}
                </div>
                <div className="map-popup__row">
                  被攻击主机：{item.hosts.length ? item.hosts.join('、') : '无'}
                </div>
                <div className="map-popup__row">最近时间：{formatTime(item.last_seen)}</div>
              </div>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
}
