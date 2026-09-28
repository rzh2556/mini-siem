/** 规则格式说明抽屉：展示内部 YAML 规则标准、算子清单，并提供模板下载。 */
import { Button, Drawer, Space, Table, Tag, Typography } from 'antd';
import { DownloadOutlined } from '@ant-design/icons';

interface RuleFormatHelpDrawerProps {
  open: boolean;
  onClose: () => void;
}

/** 可下载的 YAML 规则模板内容（覆盖三种规则类型的写法）。 */
const RULE_TEMPLATE = `# Mini-SIEM 检测规则模板
# 一个文件可放多条规则（顶层 rules: 列表），也可只写单条规则（直接写字段）。
# 文件放入 backend/rules/ 目录（英文文件名、.yml 后缀），60 秒内热加载，也可在规则页手动点“重新加载”。

rules:
  # ---------- 1. 特征匹配规则：all_of 全部满足 且 any_of 任一满足 ----------
  - id: demo-windows-failed-login
    name: 示例-Windows 登录失败
    description: 安全日志出现 4625 登录失败事件
    severity: medium            # low / medium / high / critical
    type: match                 # match=特征匹配
    enabled: true
    log_types: [windows]        # any 或 nginx/apache/ssh/windows/syslog/linux
    tags: [demo, windows]
    all_of:                     # 以下条件必须全部成立
      - field: event_id
        equals: 4625
      - field: user
        contains: admin         # 包含子串（大小写不敏感）
    any_of: []                  # 任一成立即可；与 all_of 为 AND 关系
    suppression:                # 降噪（可选）
      cooldown: 300             # 同规则同分组 300 秒内聚合为一条告警
      ignore_ips: [127.0.0.1]
      ignore_internal: false

  # ---------- 2. 阈值统计规则：时间窗口内同分组达到次数 ----------
  - id: demo-ssh-brute-force
    name: 示例-SSH 暴力破解
    description: 5 分钟内同一源 IP 登录失败超过 10 次
    severity: high
    type: threshold
    enabled: true
    log_types: [ssh]
    tags: [demo, brute-force]
    all_of:
      - field: message
        regex: 'Failed password' # 正则（re.search 子串语义，大小写不敏感）
    threshold:
      count: 10                  # 窗口内命中次数
      window: 300                # 统计窗口（秒）
      group_by: [src_ip]         # 分组字段

  # ---------- 3. 首次出现规则：回溯期内第一次见到某字段值 ----------
  - id: demo-first-seen-user
    name: 示例-新用户首次登录
    description: 30 天回溯期内首次出现的登录用户
    severity: low
    type: first_seen
    enabled: true
    log_types: [ssh, windows]
    tags: [demo]
    all_of:
      - field: event_id
        in: [4624, 4648]         # 属于列表（等价于多个 equals 的 OR）
    first_seen_field: user       # 观测字段
    first_seen_lookback: 2592000 # 回溯时长（秒），默认 30 天

  # ---------- 可用条件算子（每个条件只填一种算子） ----------
  # field:         归一化字段名，如 src_ip/user/event_id/process/command/url/status_code/raw 等
  # equals:        精确相等（数字或字符串）
  # contains:      包含子串
  # not_contains:  不包含子串
  # regex:         正则表达式
  # in:            属于列表，如 [4624, 4625]
  # not_in:        不属于列表
  # gt / lt:       数值大于 / 小于
  #
  # ---------- 可选：时间窗条件（非工作时间检测等） ----------
  # time_window:
  #   start: '08:00'
  #   end: '20:00'
  #   mode: outside              # outside=时间窗外才告警 / inside=时间窗内告警
`;

/** 算子清单表格数据 */
const OPERATOR_ROWS = [
  { op: 'equals', meaning: '精确相等', example: 'equals: 4625' },
  { op: 'contains', meaning: '包含子串（大小写不敏感）', example: 'contains: admin' },
  { op: 'not_contains', meaning: '不包含子串', example: 'not_contains: healthcheck' },
  { op: 'regex', meaning: '正则匹配（子串语义）', example: "regex: 'Failed\\s+password'" },
  { op: 'in', meaning: '属于列表（多值 OR）', example: 'in: [4624, 4625]' },
  { op: 'not_in', meaning: '不属于列表', example: 'not_in: [SYSTEM, -]' },
  { op: 'gt / lt', meaning: '数值大于 / 小于', example: 'gt: 500' },
];

/** 常用归一化字段 */
const COMMON_FIELDS = [
  'raw', 'message', 'host', 'src_ip', 'dst_ip', 'user', 'method', 'url', 'path',
  'status_code', 'user_agent', 'event_id', 'channel', 'process', 'command',
];

/** 触发浏览器下载 YAML 模板文件。 */
function downloadTemplate() {
  const blob = new Blob([RULE_TEMPLATE], { type: 'text/yaml;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'mini-siem-rule-template.yml';
  link.click();
  URL.revokeObjectURL(url);
}

/** 渲染规则格式说明抽屉。 */
export default function RuleFormatHelpDrawer({ open, onClose }: RuleFormatHelpDrawerProps) {
  return (
    <Drawer
      title="规则格式标准（YAML）"
      open={open}
      onClose={onClose}
      width={760}
      extra={
        <Button type="primary" icon={<DownloadOutlined />} onClick={downloadTemplate}>
          下载 YAML 模板
        </Button>
      }
    >
      <Typography.Paragraph>
        Mini-SIEM 的检测规则使用 <Typography.Text strong>YAML</Typography.Text> 格式，每个文件可包含一条或多条规则。
        除了在本页面用「新增规则」表单创建、用「导入 Sigma 规则」转换外，也可以直接写 YAML 文件放入{' '}
        <Typography.Text code>backend/rules/</Typography.Text> 目录，默认 60 秒自动热加载（或点页面上的「重新加载规则文件」立即生效）。
      </Typography.Paragraph>

      <Typography.Title level={5}>三种规则类型</Typography.Title>
      <ul>
        <li>
          <Tag color="blue">match</Tag>特征匹配：日志满足全部条件即告警，最常用。
        </li>
        <li>
          <Tag color="orange">threshold</Tag>阈值统计：统计窗口（window 秒）内，同一分组（group_by 字段）命中达到
          count 次才告警，适合暴力破解、接口刷量。
        </li>
        <li>
          <Tag color="purple">first_seen</Tag>首次出现：回溯期（first_seen_lookback 秒）内第一次见到某字段值时告警，适合发现新账号、新进程。
        </li>
      </ul>

      <Typography.Title level={5}>顶层字段</Typography.Title>
      <Typography.Paragraph style={{ fontSize: 13 }}>
        <Typography.Text code>id</Typography.Text> 唯一 ID（小写字母/数字/中划线/下划线）；
        <Typography.Text code>name</Typography.Text> 名称；
        <Typography.Text code>description</Typography.Text> 描述；
        <Typography.Text code>severity</Typography.Text> 等级 low/medium/high/critical；
        <Typography.Text code>type</Typography.Text> 规则类型；
        <Typography.Text code>enabled</Typography.Text> 是否启用；
        <Typography.Text code>log_types</Typography.Text> 适用日志类型；
        <Typography.Text code>tags</Typography.Text> 标签；
        <Typography.Text code>all_of</Typography.Text> / <Typography.Text code>any_of</Typography.Text> 条件组；
        <Typography.Text code>threshold</Typography.Text>、
        <Typography.Text code>first_seen_field</Typography.Text>、
        <Typography.Text code>suppression</Typography.Text>、
        <Typography.Text code>time_window</Typography.Text> 为可选高级配置。
      </Typography.Paragraph>

      <Typography.Title level={5}>条件算子</Typography.Title>
      <Table
        size="small"
        rowKey="op"
        pagination={false}
        dataSource={OPERATOR_ROWS}
        columns={[
          { title: '算子', dataIndex: 'op', key: 'op', width: 130, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
          { title: '含义', dataIndex: 'meaning', key: 'meaning', width: 240 },
          { title: '示例', dataIndex: 'example', key: 'example', render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
        ]}
      />
      <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 8 }}>
        所有字符串匹配均为大小写不敏感；all_of 中条件为 AND，any_of 中条件为 OR，两个条件组之间也是 AND。
      </Typography.Paragraph>

      <Typography.Title level={5}>常用归一化字段</Typography.Title>
      <Space size={4} wrap>
        {COMMON_FIELDS.map((field) => (
          <Tag key={field}>{field}</Tag>
        ))}
      </Space>
      <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 8 }}>
        Windows 事件的 EventID 归一成 event_id、TargetUserName/SubjectUserName 归一成 user、
        Image 归一成 process、CommandLine 归一成 command；不确定字段名时可对 raw 全文匹配。
      </Typography.Paragraph>

      <Typography.Title level={5}>新增自定义规则的三种方式</Typography.Title>
      <ol>
        <li>规则管理页点「新增规则」，用表单可视化创建（推荐新手）；</li>
        <li>
          点「导入 Sigma 规则」，上传或粘贴 <Typography.Text strong>Sigma</Typography.Text> 官方 YAML
          （SigmaHQ 规则库），自动转换并保存；
        </li>
        <li>
          按本模板手写 YAML，放入 <Typography.Text code>backend/rules/</Typography.Text> 目录热加载。
        </li>
      </ol>
    </Drawer>
  );
}
