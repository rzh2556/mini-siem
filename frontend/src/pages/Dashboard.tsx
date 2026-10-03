/** 仪表盘页面：展示核心指标、日志/告警趋势、分布图与 TOP 排行，30 秒自动刷新。 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { Card, Col, Empty, Row, Segmented, Table, Tag } from 'antd';
import { AlertOutlined, BugOutlined, FileTextOutlined, ThunderboltOutlined } from '@ant-design/icons';
import ReactECharts from 'echarts-for-react';
import type { EChartsOption } from 'echarts';
import type { ColumnsType } from 'antd/es/table';
import dayjs from 'dayjs';
import { fetchGeo, fetchOverview, fetchTimeline } from '../api/endpoints';
import type {
  GeoAttacker,
  NameCount,
  OverviewResponse,
  Severity,
  TimelineResponse,
  TopSrcIp,
} from '../api/types';
import AttackMap from '../components/AttackMap';
import SeverityTag, { SEVERITY_COLORS, SEVERITY_LABELS } from '../components/SeverityTag';
import StatCard from '../components/StatCard';
import { formatNumber } from '../utils/format';

/** 可选统计时间范围 */
const RANGE_OPTIONS = [
  { label: '最近 1 小时', value: 1 },
  { label: '最近 6 小时', value: 6 },
  { label: '最近 24 小时', value: 24 },
  { label: '最近 7 天', value: 168 },
  { label: '最近 30 天', value: 720 },
];

/** 时间范围对应的趋势图分桶间隔（与后端允许的 interval 取值保持一致） */
const INTERVAL_BY_HOURS: Record<number, string> = {
  1: '10m',
  6: '30m',
  24: '1h',
  168: '6h',
  720: '1d',
};

/** 图表坐标轴与分割线配色 */
const AXIS_COLOR = '#8b98a5';
const SPLIT_COLOR = '#243040';
const TOOLTIP_STYLE = {
  backgroundColor: '#1a222c',
  borderColor: '#2a3441',
  textStyle: { color: '#e6f0fa' },
};

/** 自动刷新间隔（毫秒） */
const REFRESH_INTERVAL = 30000;

/** 渲染仪表盘页面。 */
export default function Dashboard() {
  const [hours, setHours] = useState(24);
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null);
  const [geo, setGeo] = useState<GeoAttacker[]>([]);
  const [loading, setLoading] = useState(true);

  /** 加载总览、趋势与地图数据，错误提示由 axios 拦截器统一处理 */
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [overviewData, timelineData, geoData] = await Promise.all([
        fetchOverview(hours),
        fetchTimeline(hours, INTERVAL_BY_HOURS[hours] ?? '1h'),
        fetchGeo(hours),
      ]);
      setOverview(overviewData);
      setTimeline(timelineData);
      setGeo(geoData.attackers);
    } catch {
      // 请求失败时保留上一次数据，仅结束加载态
    } finally {
      setLoading(false);
    }
  }, [hours]);

  // 时间范围变化时立即刷新，并每 30 秒自动刷新一次；卸载时清除定时器
  useEffect(() => {
    load();
    const timer = window.setInterval(load, REFRESH_INTERVAL);
    return () => window.clearInterval(timer);
  }, [load]);

  const points = timeline?.points ?? [];
  const distribution = overview?.severity_distribution;
  const topRules = overview?.top_rules ?? [];
  const sourceTypes = overview?.source_types ?? [];
  const topSrcIps = overview?.top_src_ips ?? [];
  const hosts = overview?.hosts ?? [];

  /** 日志/告警双 Y 轴趋势折线图配置 */
  const timelineOption: EChartsOption = useMemo(
    () => ({
      backgroundColor: 'transparent',
      tooltip: { trigger: 'axis', ...TOOLTIP_STYLE },
      legend: { data: ['日志量', '告警量'], textStyle: { color: AXIS_COLOR }, top: 0 },
      grid: { left: 60, right: 60, top: 42, bottom: 46 },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: points.map((point) => dayjs(point.time).format('MM-DD HH:mm')),
        axisLine: { lineStyle: { color: SPLIT_COLOR } },
        axisLabel: { color: AXIS_COLOR, hideOverlap: true },
      },
      yAxis: [
        {
          type: 'value',
          name: '日志',
          nameTextStyle: { color: AXIS_COLOR },
          axisLabel: { color: AXIS_COLOR },
          splitLine: { lineStyle: { color: SPLIT_COLOR } },
        },
        {
          type: 'value',
          name: '告警',
          nameTextStyle: { color: AXIS_COLOR },
          axisLabel: { color: AXIS_COLOR },
          splitLine: { show: false },
        },
      ],
      series: [
        {
          name: '日志量',
          type: 'line',
          smooth: true,
          showSymbol: false,
          data: points.map((point) => point.logs),
          itemStyle: { color: '#177ddc' },
          lineStyle: { width: 2 },
          areaStyle: { color: 'rgba(23,125,220,0.18)' },
        },
        {
          name: '告警量',
          type: 'line',
          smooth: true,
          showSymbol: false,
          yAxisIndex: 1,
          data: points.map((point) => point.alerts),
          itemStyle: { color: '#fa541c' },
          lineStyle: { width: 2 },
        },
      ],
    }),
    [points],
  );

  /** 告警等级分布环形图配置 */
  const severityOption: EChartsOption = useMemo(() => {
    const severities: Severity[] = ['critical', 'high', 'medium', 'low'];
    return {
      backgroundColor: 'transparent',
      tooltip: { trigger: 'item', ...TOOLTIP_STYLE },
      legend: { bottom: 0, textStyle: { color: AXIS_COLOR } },
      series: [
        {
          type: 'pie',
          radius: ['46%', '70%'],
          center: ['50%', '45%'],
          itemStyle: { borderColor: '#1a222c', borderWidth: 2 },
          label: { color: '#c7d0d9', formatter: '{b}: {c}' },
          data: severities.map((level) => ({
            name: SEVERITY_LABELS[level],
            value: distribution ? distribution[level] : 0,
            itemStyle: { color: SEVERITY_COLORS[level] },
          })),
        },
      ],
    };
  }, [distribution]);

  /** TOP 触发规则横向柱状图配置（倒序使第一名显示在顶部） */
  const ruleOption: EChartsOption = useMemo(() => {
    const ordered = [...topRules].reverse();
    return {
      backgroundColor: 'transparent',
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, ...TOOLTIP_STYLE },
      grid: { left: 8, right: 40, top: 16, bottom: 16, containLabel: true },
      xAxis: {
        type: 'value',
        axisLabel: { color: AXIS_COLOR },
        splitLine: { lineStyle: { color: SPLIT_COLOR } },
      },
      yAxis: {
        type: 'category',
        data: ordered.map((rule) => rule.name),
        axisLabel: { color: AXIS_COLOR },
        axisLine: { lineStyle: { color: SPLIT_COLOR } },
      },
      series: [
        {
          type: 'bar',
          barWidth: 14,
          data: ordered.map((rule) => rule.count),
          itemStyle: { color: '#13c2c2', borderRadius: [0, 4, 4, 0] },
          label: { show: true, position: 'right', color: AXIS_COLOR },
        },
      ],
    };
  }, [topRules]);

  /** 日志来源类型分布饼图配置 */
  const sourceOption: EChartsOption = useMemo(
    () => ({
      backgroundColor: 'transparent',
      tooltip: { trigger: 'item', ...TOOLTIP_STYLE },
      legend: { bottom: 0, textStyle: { color: AXIS_COLOR } },
      series: [
        {
          type: 'pie',
          radius: '68%',
          center: ['50%', '44%'],
          label: { color: '#c7d0d9', formatter: '{b}: {c}' },
          data: sourceTypes.map((item) => ({ name: item.name, value: item.count })),
        },
      ],
    }),
    [sourceTypes],
  );

  /** TOP 攻击源 IP 表格列定义 */
  const ipColumns: ColumnsType<TopSrcIp> = [
    {
      title: '排名',
      key: 'rank',
      width: 64,
      render: (_value, _record, index) => index + 1,
    },
    {
      title: '源 IP',
      dataIndex: 'src_ip',
      key: 'src_ip',
    },
    {
      title: '告警次数',
      dataIndex: 'count',
      key: 'count',
      width: 96,
      sorter: (a, b) => a.count - b.count,
    },
    {
      title: '国家/地区',
      dataIndex: 'country_code',
      key: 'country_code',
      width: 110,
      render: (code?: string | null) => (code ? <Tag color="blue">{code}</Tag> : '-'),
    },
    {
      title: '最高等级',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity: TopSrcIp['severity']) => <SeverityTag severity={severity} />,
    },
  ];

  /** 主机 TOP 排行表格列定义 */
  const hostColumns: ColumnsType<NameCount> = [
    {
      title: '排名',
      key: 'rank',
      width: 64,
      render: (_value, _record, index) => index + 1,
    },
    { title: '主机名', dataIndex: 'name', key: 'name' },
    { title: '日志量', dataIndex: 'count', key: 'count', width: 110 },
  ];

  const severityDistribution = distribution ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const seriousAlerts = severityDistribution.critical + severityDistribution.high;
  // 当前统计范围内是否真的有告警，用于区分“没有数据”和“图表渲染失败”
  const hasSeverityData = Object.values(severityDistribution).some((value) => value > 0);
  const alertsTotal = overview?.alerts_total ?? 0;
  const openAlerts = overview?.open_alerts ?? 0;
  const rangeLabel = RANGE_OPTIONS.find((item) => item.value === hours)?.label ?? '';

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">安全态势总览</h2>
          <div className="page-subtitle">
            统计范围：{rangeLabel} · 每 30 秒自动刷新
          </div>
        </div>
        <div className="page-toolbar">
          <Segmented
            value={hours}
            options={RANGE_OPTIONS}
            onChange={(value) => setHours(Number(value))}
          />
        </div>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            title="日志总量"
            value={overview?.logs_total ?? 0}
            icon={<FileTextOutlined />}
            color="#177ddc"
            hint={`统计范围：${rangeLabel}`}
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            title="告警总量"
            value={alertsTotal}
            icon={<AlertOutlined />}
            color="#13c2c2"
            hint={`未处理 ${formatNumber(openAlerts)} 条`}
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            title="未处理告警"
            value={openAlerts}
            icon={<BugOutlined />}
            color="#faad14"
            hint={
              alertsTotal > 0
                ? `占全部告警 ${((openAlerts / alertsTotal) * 100).toFixed(1)}%`
                : '暂无告警'
            }
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            title="严重告警数"
            value={seriousAlerts}
            icon={<ThunderboltOutlined />}
            color="#cf1322"
            hint={`严重 ${severityDistribution.critical} · 高危 ${severityDistribution.high}`}
          />
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={16}>
          <Card
            title={<span className="card-title">日志与告警时间趋势</span>}
            loading={loading && !overview}
          >
            <ReactECharts
              className="chart-block"
              style={{ height: 320 }}
              option={timelineOption}
              notMerge
            />
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card
            title={<span className="card-title">告警等级分布</span>}
            loading={loading && !overview}
          >
            {hasSeverityData ? (
              <ReactECharts
                className="chart-block"
                style={{ height: 320 }}
                option={severityOption}
                notMerge
              />
            ) : (
              // 无数据时给出明确空态，避免被误认为“日志上传没生效”
              <div style={{ height: 320, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description={`${rangeLabel}内暂无告警，可切换到更大的统计范围`}
                />
              </div>
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={12}>
          <Card title={<span className="card-title">TOP 攻击源 IP</span>}>
            <Table
              rowKey="src_ip"
              size="small"
              loading={loading && !overview}
              columns={ipColumns}
              dataSource={topSrcIps}
              pagination={false}
              scroll={{ y: 300 }}
            />
          </Card>
        </Col>
        <Col xs={24} xl={12}>
          <Card title={<span className="card-title">TOP 触发规则</span>}>
            <ReactECharts
              className="chart-block"
              style={{ height: 340 }}
              option={ruleOption}
              notMerge
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={12}>
          <Card title={<span className="card-title">日志来源类型分布</span>}>
            <ReactECharts
              className="chart-block"
              style={{ height: 320 }}
              option={sourceOption}
              notMerge
            />
          </Card>
        </Col>
        <Col xs={24} xl={12}>
          <Card title={<span className="card-title">主机 TOP 排行</span>}>
            <Table
              rowKey="name"
              size="small"
              loading={loading && !overview}
              columns={hostColumns}
              dataSource={hosts}
              pagination={false}
              scroll={{ y: 260 }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={24}>
          <Card title={<span className="card-title">攻击地图</span>}>
            <AttackMap attackers={geo} height={380} />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
