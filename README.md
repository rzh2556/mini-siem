# Mini SIEM 日志威胁检测平台

一个可一键部署到服务器的迷你 SIEM 系统：采集 **Linux（Nginx / Apache / SSH / 系统日志）** 与 **Windows 事件日志**，通过 **YAML 规则引擎** 检测暴力破解、SQL 注入、目录扫描、异常登录等攻击行为，完成告警聚合去重降噪，并提供 **GeoIP 攻击地图** 与可视化 Dashboard。

```
                     ┌────────────────────────────────────────────────┐
   被监控主机         │              Mini SIEM 服务端（Docker）          │
 ┌──────────────┐    │                                                │
 │ Linux 服务器  │    │   ┌───────────┐   ┌────────────┐   ┌────────┐  │
 │  nginx/ssh   │──┐ │   │ FastAPI   │──▶│ 规则引擎    │──▶│ 告警聚合 │  │
 │  apache 日志 │  │ │   │ 采集入口   │   │ 阈值/正则/  │   │ 去重降噪 │  │
 └──────────────┘  │ │   │ /api/v1   │   │ 首次出现    │   └────┬───┘  │
 ┌──────────────┐  ├─┼──▶│  /ingest  │   └────────────┘        │      │
 │ Windows 服务器│  │ │   └───────────┘                         ▼      │
 │  事件日志     │──┘ │     归一化解析        ┌───────────────────────┐ │
 │ (pywin32)    │    │   Nginx/Apache/SSH/    │ Elasticsearch 存储     │ │
 └──────────────┘    │   Windows/Syslog       │ 日志索引 + 告警索引     │ │
                     │                        └───────────┬───────────┘ │
                     │   ┌────────────────────────────────▼─────────┐ │
                     │   │ React + AntD 前端：Dashboard / 告警中心 /  │ │
                     │   │ 日志检索 / GeoIP 攻击地图 / 规则管理        │ │
                     │   └──────────────────────────────────────────┘ │
                     └────────────────────────────────────────────────┘
```

## 一、核心功能

| 模块 | 能力 |
| --- | --- |
| 日志采集 | Agent 增量采集日志文件（支持轮转、断点续采），Windows 事件日志（Security/System，pywin32）；也支持 `curl` 直接推送原始文本 |
| 归一化解析 | Nginx/Apache 访问与错误日志、SSH 认证日志（失败/成功/无效用户/sudo）、Syslog（RFC3164/5424）、Windows 事件 XML，统一为标准字段模型 |
| 规则检测 | YAML 规则，支持正则/等值/包含/数值比较、`all_of`/`any_of` 组合、时间窗条件；三类规则：`match`（单条即告警）、`threshold`（窗口内 N 次计数）、`first_seen`（首次出现，识别陌生来源登录） |
| 告警聚合降噪 | 冷却窗口内同规则同分组合并为一条告警并累加次数、IP 白名单、内网源抑制、最低等级过滤、样本留存 |
| 可视化 | 指标卡、日志/告警趋势双轴折线图、等级分布、TOP 攻击源、TOP 规则、来源类型与主机分布、GeoIP 世界攻击地图 |
| 运维 | Docker Compose 一键部署、规则文件热加载、日志索引按天切分并按保留期自动清理、健康检查接口 |

## 二、技术栈

- **后端**：Python 3.11 + FastAPI + Pydantic v2 + elasticsearch-py（异步）
- **存储**：Elasticsearch 8（日志索引 `siem-logs-YYYY.MM.DD` + 告警索引 `siem-alerts`）
- **规则引擎**：自研 YAML 规则引擎（正则 + 阈值滑动窗口 + 首次出现检测）
- **前端**：React 18 + TypeScript + Vite + Ant Design 5 + ECharts + Leaflet
- **采集**：纯标准库实现的轻量 Agent（Windows 事件采集额外需要 pywin32）
- **部署**：Docker Compose（Elasticsearch + 后端 + Nginx 前端）

> 关于 ClickHouse：本项目存储层集中在 `backend/app/storage/es_client.py`，只暴露写入/检索/聚合三类接口。ES 胜在日志全文检索与开箱即用的聚合分析；若你的场景是海量日志（每日 TB 级）且以统计聚合为主，可把该文件替换为 ClickHouse 实现，其余代码（解析、规则、告警、API）无需改动。

## 三、快速开始（服务器部署）

### 1. 环境要求

- Linux 服务器（2 核 4G 起，Elasticsearch 建议至少分配 1G 堆内存）
- Docker 20.10+ 与 Docker Compose v2
- 首次使用需调整内核参数（Elasticsearch 要求）：

```bash
sudo sysctl -w vm.max_map_count=262144
# 永久生效
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### 2. 启动

```bash
git clone <你的仓库地址> mini-siem && cd mini-siem
cp .env.example .env
vim .env          # 必须修改 AGENT_TOKEN；公网部署建议同时设置 API_TOKEN
docker compose up -d --build
```

查看启动进度（首次启动 Elasticsearch 需 1~2 分钟）：

```bash
docker compose logs -f backend
# 出现 “Elasticsearch 连接成功，索引已就绪” 即为就绪
curl http://127.0.0.1/api/v1/health
```

### 3. 访问

| 地址 | 说明 |
| --- | --- |
| `http://<服务器IP>/` | 前端控制台（Dashboard / 告警 / 日志 / 攻击地图 / 规则） |
| `http://<服务器IP>:8000/docs` | 后端 Swagger API 文档 |
| `http://127.0.0.1:9200` | Elasticsearch（仅本机可访问） |

### 4. 推送演示数据验证

```bash
python3 scripts/generate_demo_logs.py --url http://127.0.0.1:8000 --token <你的AGENT_TOKEN>
```

脚本会模拟 SSH 暴力破解、SQL 注入、目录扫描、Windows 登录爆破与日志清空，10 秒后即可在 Dashboard 看到告警。

## 四、部署采集 Agent

### Linux 主机

```bash
# 1. 拷贝 agent 目录到被监控主机
scp -r agent/ user@target-host:/opt/siem-agent/

# 2. 修改配置（服务端地址、令牌、日志路径）
cd /opt/siem-agent
cp config.example.yml config.yml
vim config.yml

# 3. 前台试跑一次，确认能上报
python3 siem_agent.py --config config.yml --once

# 4. 注册为 systemd 常驻服务
sudo tee /etc/systemd/system/siem-agent.service > /dev/null <<'EOF'
[Unit]
Description=Mini SIEM Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/siem-agent
ExecStart=/usr/bin/python3 /opt/siem-agent/siem_agent.py --config /opt/siem-agent/config.yml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now siem-agent
sudo systemctl status siem-agent
```

> 需要读取 `/var/log/auth.log`、Nginx 日志时，请用 root 或具备对应文件读权限的账号运行；也可将日志通过 `rsyslog` 转发后再采集。

### Windows 主机

```powershell
# 1. 安装依赖（建议用管理员 PowerShell）
cd C:\siem-agent
pip install -r requirements-windows.txt

# 2. 修改 config.example.yml -> config.yml，把 windows-security / windows-system 的 enabled 改为 true，
#    并填写 server.url 与 server.token

# 3. 试跑一次
python siem_agent.py --config config.yml --once

# 4. 注册为计划任务，开机自动运行
schtasks /create /tn "MiniSIEMAgent" /tr "python C:\siem-agent\siem_agent.py --config C:\siem-agent\config.yml" /sc onstart /ru SYSTEM /rl HIGHEST
schtasks /run /tn "MiniSIEMAgent"
```

> Windows 事件日志读取需要以管理员权限运行。采集的事件 ID 默认包含 4624/4625/4648/4672/4720/4726/4732/4740/1102/7045。

### 其他接入方式（无需 Agent）

```bash
# 推送单行文本日志（每行一条）
tail -n 100 /var/log/nginx/access.log | \
  curl -X POST "http://127.0.0.1:8000/api/v1/ingest/raw?host=web-01&source_type=nginx" \
       -H "X-Agent-Token: <你的AGENT_TOKEN>" --data-binary @-
```

#### 上传日志文件并解析（历史日志导入）

控制台「日志检索」页右上角的 **上传日志文件** 按钮可直接选择本地日志文件上传，自动识别类型、解析入库并展示命中规则，适用于导入历史日志或排查离线样本。

也可用命令行上传：

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/ingest/upload" \
     -H "Authorization: Bearer <你的API_TOKEN>" \
     -F "file=@/var/log/nginx/access.log" \
     -F "host=web-01" \
     -F "source_type=auto"      # auto 表示自动识别，也可指定 nginx/apache/ssh/linux/windows/syslog
```

返回字段：`filename`、`source_type`（实际使用的类型）、`auto_detected`（是否为自动识别）、`total_lines`、`accepted`（入库条数）、`skipped`（超出上限被跳过条数）、`alerts`（新增告警数）、`preview`（前 5 条解析结果与命中规则）。

限制与说明：单文件最大 50MB、最多解析 20 万行（超出部分计入 `skipped`），建议按天切分后分批上传；日志编码自动兼容 UTF-8 / GBK / UTF-16；Windows 事件日志（`.evtx`）为二进制格式，请使用采集 Agent 上报。

## 五、检测规则

规则文件位于 `backend/rules/*.yml`，通过 `./backend/rules` 目录挂载进容器，**修改后 60 秒内自动热加载**，也可在「规则管理」页点击“重新加载规则文件”立即生效。

### 规则示例

```yaml
id: ssh-bruteforce                 # 唯一标识
name: SSH 暴力破解
description: "源 IP {src_ip} 在 300 秒内连续失败 {count} 次"   # {} 中可用正则命名分组与事件字段
severity: high                     # low / medium / high / critical
type: threshold                    # match 单条告警 / threshold 阈值计数 / first_seen 首次出现
log_types: [ssh, linux, syslog]    # 适用日志类型，any 表示全部
tags: [attack.bruteforce, T1110]   # 标签，可写 MITRE ATT&CK 编号
all_of:                            # 全部条件满足（any_of 为任一满足）
  - field: raw                     # 支持字段：raw/message/url/path/query/user/src_ip/status_code/event_id/user_agent/command...
    regex: "Failed password for (?:invalid user )?(?P<user>\\S+) from (?P<src_ip>[0-9a-fA-F:.]+)"
threshold:
  count: 5                         # 窗口内命中次数
  window: 300                      # 窗口秒数
  group_by: [src_ip]               # 分组维度，同组独立计数
suppression:
  cooldown: 900                    # 冷却期内同组告警合并为一条（降噪）
  ignore_ips: []                   # 该规则额外的白名单 IP
  ignore_internal: false           # 是否忽略内网源
```

**条件判断关键字**：`regex`（正则，命名分组可用于描述模板与分组）、`equals`、`contains`、`in`、`not_in`、`gt`、`lt`。
**时间窗**：`time_window: {start: "08:00", end: "20:00", mode: outside}` 用于非工作时间登录检测。
**首次出现**：`type: first_seen` + `first_seen_field: "src_ip,user"` + `first_seen_lookback: 2592000`，用于识别陌生 IP/账号登录。

### 内置规则一览（26 条）

| 分类 | 规则 |
| --- | --- |
| SSH / Linux | SSH 暴力破解、用户名枚举、root 远程登录成功、异常登录（陌生 IP / 非工作时间）、sudo 提权失败、新建系统账号、authorized_keys 被修改 |
| Web | SQL 注入、目录穿越、XSS、命令注入、敏感文件探测、WebShell 访问、目录扫描/爆破、已知扫描器 UA、5xx 错误激增 |
| Windows | 登录爆破(4625)、账号锁定(4740)、显式凭据登录(4648)、授予特殊权限(4672)、新建账号(4720)、加入管理员组(4732)、日志清空(1102)、安装服务(7045)、非工作时间 RDP 登录 |

## 六、告警降噪机制

1. **阈值计数**：频率类规则在滑动窗口内计数，达标才告警（避免单条噪音）。
2. **冷却合并**：同规则 + 同分组在 `cooldown` 秒内只保留一条告警，后续命中使 `count` 累加并刷新 `last_seen`。
3. **白名单与内网抑制**：`.env` 的 `IP_WHITELIST`、规则级 `ignore_ips`、`ignore_internal`。
4. **等级过滤**：`MIN_ALERT_SEVERITY` 以下的告警直接丢弃。
5. **样本截断**：每条告警最多保留 10 条原始日志样本，控制存储膨胀。

## 七、配置项（.env）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ES_URL` | `http://elasticsearch:9200` | Elasticsearch 地址 |
| `ES_RETENTION_DAYS` | `30` | 日志索引保留天数，超期自动删除 |
| `AGENT_TOKEN` | `change-me-agent-token` | Agent 上报令牌，**必须修改** |
| `API_TOKEN` | 空 | 控制台/API 访问令牌，留空则不校验 |
| `GEOIP_DB_PATH` | `/app/geoip/GeoLite2-City.mmdb` | GeoLite2 离线库路径 |
| `GEOIP_ONLINE_FALLBACK` | `true` | 无离线库时是否使用 ip-api.com 在线解析 |
| `ALERT_COOLDOWN` | `300` | 全局告警合并窗口（秒） |
| `MIN_ALERT_SEVERITY` | `low` | 低于该等级的告警丢弃 |
| `IP_WHITELIST` | `127.0.0.1,::1` | 全局白名单 IP |
| `IGNORE_INTERNAL_SRC` | `false` | 是否忽略内网源 IP 的告警 |
| `ES_HEAP` | `1g` | Elasticsearch JVM 堆大小 |

## 八、GeoIP 攻击地图

攻击地图需要 IP 归属地数据，按以下优先级解析：

1. **离线库（推荐，内网可用）**：把 `GeoLite2-City.mmdb` 放到 `geoip/` 目录（[MaxMind 免费注册下载](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)），重启后端即可。
2. **在线接口**：未配置离线库且 `GEOIP_ONLINE_FALLBACK=true` 时，调用 `ip-api.com` 免费接口（带 1.4 秒节流与内存缓存，仅解析公网 IP）。
3. **降级**：都不可用时地图显示为空提示，不影响检测与告警功能。

## 九、API 概览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/ingest` | 批量上报日志（需 `X-Agent-Token`） |
| POST | `/api/v1/ingest/raw` | 上报纯文本日志（每行一条） |
| POST | `/api/v1/ingest/upload` | 上传日志文件并解析入库（multipart，需控制台令牌） |
| GET | `/api/v1/logs/search` | 多条件日志检索（全文/类型/主机/IP/等级/命中规则/时间） |
| GET | `/api/v1/logs/filters` | 获取筛选项（类型、主机、等级） |
| GET | `/api/v1/alerts` | 告警列表（状态/等级/规则/源IP/关键词/时间） |
| GET | `/api/v1/alerts/{id}` | 告警详情（含原始日志样本） |
| PATCH | `/api/v1/alerts/{id}` | 更新告警状态与备注 |
| POST | `/api/v1/alerts/bulk` | 批量更新告警状态 |
| GET | `/api/v1/rules` | 规则列表 |
| PATCH | `/api/v1/rules/{id}` | 在线启停规则 / 调整等级与阈值 |
| POST | `/api/v1/rules/reload` | 重新加载规则文件 |
| GET | `/api/v1/stats/overview` | 总览指标与 TOP 排行 |
| GET | `/api/v1/stats/timeline` | 日志与告警时间趋势 |
| GET | `/api/v1/stats/geo` | 攻击地图数据 |
| GET | `/api/v1/stats/attackers` | 攻击源排行榜 |
| GET | `/api/v1/health` | 健康检查 |

## 十、目录结构

```
mini-siem/
├── docker-compose.yml            # 一键部署编排
├── .env.example                  # 环境变量模板
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── rules/                    # 检测规则（挂载进容器，支持热加载）
│   │   ├── ssh_auth.yml
│   │   ├── web_attacks.yml
│   │   └── windows_events.yml
│   └── app/
│       ├── main.py               # 应用入口与后台维护任务
│       ├── config.py             # 配置
│       ├── state.py              # 全局单例容器
│       ├── api/                  # ingest / logs / alerts / rules / stats
│       ├── normalize/parsers.py  # 各来源日志归一化解析
│       ├── engine/               # rule_loader / matcher / aggregator / pipeline / geoip
│       ├── models/schemas.py     # 数据模型
│       └── storage/es_client.py  # Elasticsearch 存储层
├── frontend/                     # React 控制台（Vite + AntD + ECharts + Leaflet）
├── agent/                        # 采集 Agent（Linux/Windows 通用）
└── scripts/generate_demo_logs.py # 演示数据生成
```

## 十一、常见问题

**Elasticsearch 启动失败 / 容器反复重启**
先确认 `vm.max_map_count >= 262144`；内存不足时调小 `ES_HEAP`（如 `512m`）或升级服务器配置。

**日志进不来、日志检索为空**
1. 检查 Agent 日志中的报错，确认 `server.url` 与 `token` 正确；
2. `curl http://<服务器>:8000/api/v1/health` 确认 `elasticsearch: true`；
3. 日志只有在**新产生**时才会被采集，历史日志需用 `/ingest/raw` 或控制台「上传日志文件」导入。

**告警迟迟不出现**
频率类规则需要达到阈值（例如 SSH 暴力破解 300 秒内 5 次）；另外检查 `.env` 的 `MIN_ALERT_SEVERITY` 是否把低等级告警过滤掉了。

**攻击地图没有数据**
参考第八节配置 GeoIP；内网 IP 与保留地址不会解析，属正常现象。

**时间显示不对**
容器已设置 `TZ=Asia/Shanghai`，前端按浏览器本地时区展示；如服务器时区不同，可在 `docker-compose.yml` 中调整 `TZ`。

## 十二、安全加固建议

1. 修改默认 `AGENT_TOKEN`，并设置 `API_TOKEN` 防止控制台被未授权访问。
2. 生产环境请在 Nginx 前置 HTTPS，或只通过内网/VPN 暴露控制台端口。
3. Elasticsearch 端口已在编排中限制为 `127.0.0.1` 访问，请勿改为 `0.0.0.0`。
4. 远程 Agent 上报建议走内网或专用通道，避免令牌在公网明文传输。
5. 定期检查 `ES_RETENTION_DAYS` 与磁盘水位，避免磁盘写满导致 ES 进入只读状态。

## 十三、停止与卸载

```bash
docker compose down          # 停止服务（保留数据）
docker compose down -v       # 停止并删除数据卷（清空所有日志与告警）
```
