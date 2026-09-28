/** 指标卡组件：用于仪表盘顶部展示关键指标数值。 */
import type { ReactNode } from 'react';
import { Card, Statistic } from 'antd';

/** 指标卡属性 */
interface StatCardProps {
  /** 指标名称 */
  title: string;
  /** 指标数值 */
  value: number;
  /** 左侧图标 */
  icon: ReactNode;
  /** 图标与强调色 */
  color: string;
  /** 数值下方的补充说明 */
  hint?: string;
}

/** 渲染单个指标卡（图标 + 数值 + 说明）。 */
export default function StatCard({ title, value, icon, color, hint }: StatCardProps) {
  return (
    <Card className="stat-card">
      <div className="stat-card__body">
        <div
          className="stat-card__icon"
          style={{ color, backgroundColor: `${color}1f`, border: `1px solid ${color}59` }}
        >
          {icon}
        </div>
        <div className="stat-card__content">
          <Statistic
            title={title}
            value={value}
            valueStyle={{ color: '#e6f0fa', fontSize: 26, fontWeight: 600 }}
          />
          {hint ? <div className="stat-card__hint">{hint}</div> : null}
        </div>
      </div>
    </Card>
  );
}
