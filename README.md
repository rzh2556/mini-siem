# Mini SIEM 日志威胁检测平台

一个可一键部署到服务器的迷你 SIEM 系统：采集 **Linux（Nginx / Apache / SSH / 系统日志）** 与 **Windows 事件日志**，通过 **YAML 规则引擎** 检测暴力破解、SQL 注入、目录扫描、异常登录等攻击行为，完成告警聚合去重降噪，并提供 **GeoIP 攻击地图** 与可视化 Dashboard。

```
                     ┌────────────────────────────────────────────────┐
   被监控主机         │            Mini SIEM 服务端（Docker / 裸机）        │
 ┌──────────────┐    │                                                │
 │ Linux 服务器  │    │   ┌───────────┐   ┌────────────┐   ┌────────┐  │
 │  nginx/ssh   │──┐ │   │ FastAPI   │──▶│ 规则引擎    │──▶│ 告警聚合 │  │
 │  apache 日志 │  │ │   │ 采集入口   │   │ 阈值/正则/  │   │ 去重降噪 │  │
 └──────────────┘  │ │   │ /api/v1   │   │ 首次出现    │   └────┬───┘  │
 ┌──────────────┐  ├─┼──▶│  /ingest  │   └────────────┘        │      │
 │ Windows 服务器│  │ │   └───────────┘                         ▼      │
 │  事件日志     │──┘ │     归一化解析        ┌───────────────────────┐ │
 │ (pywin32)    │    │   Nginx/Apache/SSH/    │ SQLite / ES 存储       │ │
 └──────────────┘    │   Windows/Syslog       │ 日志表 + 告警表        │ │
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
| 日志采集 | Agent 增量采集日志文件（支持轮转、断点续采），Windows 事件日志（Security/System，pywin32）；支持 `curl` 推送原始文本，**页面可直接上传 `.evtx` 事件日志文件**（自动解析 EventID/用户/源IP/进程等字段） |
| 归一化解析 | Nginx/Apache 访问与错误日志、SSH 认证日志（失败/成功/无效用户/sudo）、Syslog（RFC3164/5424）、Windows 事件 XML / EVTX 二进制，统一为标准字段模型 |
| 规则检测 | YAML 规则，支持正则/等值/包含/数值比较、`all_of`/`any_of` 组合、时间窗条件；三类规则：`match`（单条即告警）、`threshold`（窗口内 N 次计数）、`first_seen`（首次出现，识别陌生来源登录）；**内置规则 + 管理后台可视化新增/编辑/删除自定义规则** |
| 账号与后台 | 管理员账号密码登录（PBKDF2-SHA256 加盐哈希 + JWT 会话），默认密码首次登录强制修改；所有页面与数据接口均需登录；后台可在线调整降噪参数、GeoIP、日志级别、CORS 并轮换采集令牌 |
| 告警聚合降噪 | 冷却窗口内同规则同分组合并为一条告警并累加次数、IP 白名单、内网源抑制、最低等级过滤、样本留存 |
| 可视化 | 指标卡、日志/告警趋势双轴折线图、等级分布、TOP 攻击源、TOP 规则、来源类型与主机分布、GeoIP 世界攻击地图 |
| 运维 | systemd 裸机一键部署（低负载）或 Docker Compose、规则文件热加载、日志按保留期自动清理、健康检查接口、`reset_admin.py` 密码重置工具 |

## 二、技术栈

- **后端**：Python 3.11 + FastAPI + Pydantic v2（异步）
- **存储**：**SQLite（默认，零依赖、低负载）** / Elasticsearch 8（可选，索引 `siem-logs-YYYY.MM.DD` + `siem-alerts`）
- **规则引擎**：自研 YAML 规则引擎（正则 + 阈值滑动窗口 + 首次出现检测）
- **前端**：React 18 + TypeScript + Vite + Ant Design 5 + ECharts + Leaflet
- **采集**：纯标准库实现的轻量 Agent（Windows 事件采集额外需要 pywin32）
- **部署**：systemd 裸机单进程（推荐，约 100~200MB 内存）或 Docker Compose

> **存储层可插拔**：存储接口集中在 `backend/app/storage/`，`sqlite_client.py` 与 `es_client.py` 对外暴露完全相同的方法与返回结构，上层 API、规则引擎、前端无需任何改动。通过 `.env` 的 `STORAGE_BACKEND` 一键切换；若要接入 ClickHouse 等其他存储，只要照抄这两个文件的接口即可。

## 三、快速开始（服务器部署）

### 部署方式怎么选

| 方式 | 内存占用 | 说明 |
| --- | --- | --- |
| **裸机 + SQLite（推荐）** | 约 100~200MB | 零依赖，单进程同时托管前后端，systemd 守护；适合 1~2G 小内存服务器 |
| Docker + SQLite | 约 300~500MB | 保留容器隔离，但不启动 Elasticsearch |
| Docker + Elasticsearch | 1.5G 以上 | 全文检索与聚合能力最强，适合 4G 以上内存 |

> 内存不足时优先选第一种。Elasticsearch 单节点默认就要占 1.5~2G 内存，是整个系统负载的主要来源。

### 方式一：裸机部署（低负载，推荐）

**环境要求**：Linux 服务器 + Python 3.8+（脚本自动检测），**不需要 Docker，也不需要 nginx**——前端构建产物由后端直接托管。

```bash
# 1. 拉取代码（也可以直接把整个目录 scp 上传）
git clone <你的仓库地址> mini-siem && cd mini-siem

# 2. 本机构建前端产物（需要 Node 18+）
cd frontend && npm ci && npm run build && cd ..

# 3. 一键部署
sudo bash deploy/install.sh
```

脚本会自动完成：安装 Python 依赖 → 创建 `minisiem` 系统用户（非 root 运行）→ 复制后端代码与规则到 `/opt/mini-siem` → 生成 `.env`（含随机采集令牌）→ 注册并启动 `mini-siem` systemd 服务 → 执行健康检查。

```bash
systemctl status mini-siem      # 查看运行状态
journalctl -u mini-siem -f      # 实时日志
curl http://127.0.0.1:8000/api/v1/health
```

可用环境变量覆盖默认值：

```bash
sudo INSTALL_DIR=/srv/mini-siem SERVICE_PORT=8000 bash deploy/install.sh
```

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `INSTALL_DIR` | `/opt/mini-siem` | 安装目录 |
| `SERVICE_PORT` | `8000` | 监听端口 |
| `AGENT_TOKEN` | 随机生成 | 采集令牌 |
| `PYPI_MIRROR` | 清华源 | pip 下载源 |

> 若服务器上已有 Node，第 2 步可跳过，脚本会自动执行 `npm ci && npm run build`；但小内存机器上构建较慢且可能 OOM，推荐在本机构建后连同 `frontend/dist` 一起上传。
> 修改配置：编辑 `/opt/mini-siem/.env` 后执行 `systemctl restart mini-siem`。
> 记得在云服务器安全组 / 防火墙放行 `8000` 端口。

### 方式二：Docker Compose 部署

#### 1. 环境要求

- Linux 服务器，Docker 20.10+ 与 Docker Compose v2
- 默认（SQLite）2 核 2G 即可；启用 Elasticsearch 建议 2 核 4G 起，并调整内核参数：

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf   # 永久生效
```

#### 2. 启动

```bash
git clone <你的仓库地址> mini-siem && cd mini-siem
cp .env.example .env
vim .env          # 必须修改 AGENT_TOKEN；ADMIN_PASSWORD 可在此预设（留空则首登用 admin123 并强制修改）
docker compose up -d --build
```

默认使用 SQLite，**不会启动 Elasticsearch**。若需要 ES，先在 `.env` 中设置 `STORAGE_BACKEND=elasticsearch`，再用 `es` profile 启动（首次启动需 1~2 分钟）：

```bash
docker compose --profile es up -d --build
docker compose logs -f backend      # 观察就绪日志
```

#### 3. 访问

| 地址 | 说明 |
| --- | --- |
| `http://<服务器IP>/` | 前端控制台（Docker 部署，经 nginx 80 端口） |
| `http://<服务器IP>:8000/` | 前端控制台（裸机部署，后端直接托管） |
| `http://<服务器IP>:8000/docs` | 后端 Swagger API 文档 |
| `http://127.0.0.1:9200` | Elasticsearch（仅本机可访问，仅启用 es profile 时存在） |

### 4. 首次登录

浏览器打开控制台后会跳转登录页，使用默认账号 **admin / admin123** 登录，**首次登录强制修改密码**（至少 8 位）。密码以 PBKDF2-SHA256 加盐哈希保存在系统库 `data/system.db` 中；忘记密码可在服务器执行：

```bash
cd /opt/mini-siem/backend          # Docker 部署可忽略本方式
../venv/bin/python reset_admin.py  # 随机生成新密码；也可跟参数直接指定
```

如需在首次部署前自定义初始账号/密码，在 `.env` 中设置 `ADMIN_USERNAME`、`ADMIN_PASSWORD`（见 `.env.example`）。

### 5. 推送演示数据验证

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

支持两类文件：

- **文本日志**：Nginx/Apache/SSH/Syslog/Windows 事件 XML 等纯文本，按行解析；
- **Windows EVTX 事件文件（`.evtx`，二进制）**：从「事件查看器」中右键日志类别 →「将所有事件另存为」得到；后端解析二进制记录后自动提取 EventID、等级、通道、计算机名、事件时间，以及 `SubjectUserName`/`TargetUserName`（用户）、`IpAddress`（源 IP）、进程名与命令行等字段，命中规则同样产生告警。

也可用命令行上传（文本与 `.evtx` 相同接口）：

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/ingest/upload" \
     -H "Authorization: Bearer <登录JWT或API_TOKEN>" \
     -F "file=@/tmp/security.evtx" \
     -F "host=dc-01" \
     -F "source_type=auto"      # auto 表示自动识别，也可指定 nginx/apache/ssh/linux/windows/syslog
```

返回字段：`filename`、`source_type`（实际使用的类型）、`auto_detected`（是否为自动识别）、`total_lines`、`accepted`（入库条数）、`skipped`（超出上限被跳过条数）、`alerts`（新增告警数）、`preview`（前 5 条解析结果与命中规则）。

限制与说明：单文件默认最大 200MB、最多解析 20 万行/条记录（均可在「系统设置 → 文件上传」中热调整，或用 `.env` 的 `MAX_UPLOAD_MB` / `MAX_UPLOAD_LINES` 设置默认值；Docker 部署 nginx 上限为 500MB），超出大小返回 413、超出条数部分计入 `skipped`，建议按天切分后分批上传；文本日志编码自动兼容 UTF-8 / GBK / UTF-16；`.evtx` 损坏或非事件日志文件会返回 400 错误。

## 五、检测规则

规则文件位于 `backend/rules/*.yml`，通过 `./backend/rules` 目录挂载进容器，**修改后 60 秒内自动热加载**，也可在「规则管理」页点击“重新加载规则文件”立即生效。

### 5.1 三种新增/自定义规则的方式

1. **可视化表单（推荐新手）**：「规则管理」页点「新增规则」，填写基本信息（ID 仅允许小写字母/数字/`-`/`_`）、适用日志类型，用条件构造器添加 `all_of`/`any_of` 条件，并按需配置阈值、首次出现、抑制参数。自定义规则持久化在 `custom_managed.yml`，可随时**编辑/删除**；
2. **导入 Sigma 规则**：点「导入 Sigma 规则」，上传或粘贴 [Sigma](https://github.com/SigmaHQ/sigma) 官方 YAML（支持 `---` 分隔多条），系统自动转换为内部规则并保存。详见 5.3；
3. **手写 YAML 热加载**：按 5.2 的格式写好 `.yml` 放入 `backend/rules/` 目录，60 秒内自动加载，也可在页面手动点「重新加载」。

> 内置 26 条规则为只读基线（列表中以「内置」标识），仅支持在线**启停、调整等级/阈值**，不能整体编辑或删除；自定义与 Sigma 导入的规则以「自定义」标识，可完整编辑删除。页面上点「规则格式说明」可随时查看字段标准并下载 YAML 模板。

### 5.2 规则格式标准（YAML）

一个文件可包含单条规则（直接写字段）或多条规则（顶层 `rules:` 列表）。顶层字段：

| 字段 | 说明 |
| --- | --- |
| `id` | 唯一 ID，2~64 位小写字母/数字/`-`/`_` |
| `name` / `description` | 规则名称 / 描述（描述中 `{字段名}` 与正则命名分组会被替换） |
| `severity` | `low` / `medium` / `high` / `critical` |
| `type` | `match` 特征匹配 / `threshold` 阈值统计 / `first_seen` 首次出现 |
| `enabled` | 是否启用 |
| `log_types` | 适用日志类型：`any` 或 `nginx`/`apache`/`ssh`/`windows`/`syslog`/`linux` |
| `tags` | 自由标签，可写 MITRE ATT&CK 编号 |
| `all_of` / `any_of` | 条件组：组内 AND / OR，两组之间也是 AND |
| `threshold` | 阈值规则：`count` / `window`(秒) / `group_by` |
| `first_seen_field` / `first_seen_lookback` | 首次出现规则的观测字段 / 回溯秒数（默认 30 天） |
| `time_window` | `{start: "08:00", end: "20:00", mode: outside}`，outside=窗外告警 |
| `suppression` | `cooldown` 冷却秒数 / `ignore_ips` / `ignore_internal` |

**条件算子（每个条件只填一种，字符串匹配均大小写不敏感）**：

| 算子 | 含义 | 示例 |
| --- | --- | --- |
| `equals` | 精确相等 | `equals: 4625` |
| `contains` / `not_contains` | 包含 / 不包含子串 | `contains: admin` |
| `regex` | 正则（`re.search` 子串语义，命名分组可提取字段） | `regex: 'Failed\s+password'` |
| `in` / `not_in` | 属于 / 不属于列表 | `in: [4624, 4625]` |
| `gt` / `lt` | 数值大于 / 小于 | `gt: 500` |

**常用归一化字段**：`raw`、`message`、`host`、`src_ip`、`dst_ip`、`user`、`method`、`url`、`path`、`status_code`、`user_agent`、`event_id`、`channel`、`process`、`command`。Windows 事件的 `EventID`→`event_id`、`TargetUserName`/`SubjectUserName`→`user`、`Image`→`process`、`CommandLine`→`command`。

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

### 5.3 导入 Sigma 规则

可以直接导入 [SigmaHQ 规则库](https://github.com/SigmaHQ/sigma/tree/master/rules)等来源的 Sigma YAML，转换在后端完成并逐条返回结果（已导入/跳过/失败 + 警告），**转换失败的规则会明确报错，不会静默忽略**。

支持的 Sigma 子集：

- `detection` 中任意 `selection`/`filter` 命名块，`condition` 支持 `and`/`or`/`not`/括号、`1 of them`、`all of them`、`1/all of selection*`、`1 of (a,b)`；列表型 selection（组内 AND、组间 OR）；
- 字段修饰符：`contains`(`|all`)、`startswith`、`endswith`、`re`、`base64`/`base64offset`（自动展开 UTF-8/UTF-16LE 三偏移）、`windash`（`-`/`/` 通配）、`gt/gte/lt/lte`、`nocase`（引擎本身大小写不敏感）；
- `logsource` 自动映射日志类型、`level` 自动映射严重等级，常见 Windows/Web 字段自动映射为归一化字段；未识别字段降级为 `raw` 全文匹配并给出警告；
- 内部规则模型只有“all_of AND any_of”两层，无法表达任意布尔表达式，因此 **OR 条件会自动拆成多条等价规则**（ID 加 `-1/-2` 后缀，单次最多 16 条）。

**暂不支持**（对应规则标记失败并提示原因）：`| count()` 等聚合条件与 `near` 近邻（可改用 `threshold` 阈值规则手动创建）、`cidr`、`null`、`expand` 修饰符、“N 选 M”量化。

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
| `STORAGE_BACKEND` | `sqlite` | 存储后端：`sqlite`（零依赖、低负载）/ `elasticsearch` |
| `SQLITE_PATH` | `data/siem.db` | SQLite 数据库文件路径 |
| `FRONTEND_DIST` | 空 | 前端构建产物目录，非空且存在时由后端直接托管前端（免装 nginx） |
| `ES_URL` | `http://elasticsearch:9200` | Elasticsearch 地址（`STORAGE_BACKEND=elasticsearch` 时生效） |
| `ES_RETENTION_DAYS` | `30` | 日志保留天数，超期自动清理（两种后端都生效） |
| `AGENT_TOKEN` | `change-me-agent-token` | Agent 上报令牌（`X-Agent-Token`），**必须修改**；也可在后台重新生成 |
| `API_TOKEN` | 空 | 第三方调用数据/上传接口的静态 Bearer 令牌（可选）；浏览器端始终使用管理员登录，与此无关 |
| `ADMIN_USERNAME` | `admin` | 管理员账号，首次启动时自动创建 |
| `ADMIN_PASSWORD` | 空 | 管理员初始密码，留空为 `admin123`（首次登录强制改密）；修改密码后以系统库为准 |
| `JWT_SECRET` | 空 | JWT 签名密钥，留空则首次启动随机生成并持久化到系统库 |
| `TOKEN_EXPIRE_HOURS` | `12` | 登录令牌有效期（小时） |
| `SYSTEM_DB_PATH` | `data/system.db` | 账号、密码、后台配置的独立系统库路径 |
| `GEOIP_DB_PATH` | `/app/geoip/GeoLite2-City.mmdb` | GeoLite2 离线库路径 |
| `GEOIP_ONLINE_FALLBACK` | `true` | 无离线库时是否使用 ip-api.com 在线解析 |
| `ALERT_COOLDOWN` | `300` | 全局告警合并窗口（秒） |
| `MIN_ALERT_SEVERITY` | `low` | 低于该等级的告警丢弃 |
| `IP_WHITELIST` | `127.0.0.1,::1` | 全局白名单 IP |
| `IGNORE_INTERNAL_SRC` | `false` | 是否忽略内网源 IP 的告警 |
| `MAX_UPLOAD_MB` | `200` | 控制台单文件上传大小上限（MB），后台「系统设置」可热改 |
| `MAX_UPLOAD_LINES` | `200000` | 单文件最多解析的日志/事件条数，超出计入 skipped |
| `ES_HEAP` | `1g` | Elasticsearch JVM 堆大小（仅 Docker + es profile 使用） |

### 7.1 配置文件在哪里

| 部署方式 | 配置文件 | 数据目录 |
| --- | --- | --- |
| 裸机（systemd） | `/opt/mini-siem/.env` | `/opt/mini-siem/data/`（`siem.db` 等） |
| Docker Compose | 项目根目录 `.env`（由 `.env.example` 复制） | 宿主项目根目录 `./data/` |

### 7.2 改完配置怎么生效

```bash
# 裸机
sudo vim /opt/mini-siem/.env
sudo systemctl restart mini-siem

# Docker（compose 会自动重建受影响的容器）
vim .env
docker compose up -d
```

> 规则文件（`rules/*.yml`）**不需要重启**，保存后 60 秒内自动热加载；也可在「规则管理」页点“重新加载规则文件”立即生效。
>
> 常用降噪与运行参数（保留天数、冷却、最低等级、白名单、内网抑制、GeoIP 在线开关、日志级别等）也可直接在「系统设置」页修改，**保存即热生效，无需重启**；仅 `CORS_ORIGINS`、`GEOIP_DB_PATH` 等少数启动项需要重启。

### 7.3 常见配置改法

**① 修改访问端口**

```bash
# 裸机：重跑安装脚本并指定端口（脚本会同步更新 systemd 单元）
sudo SERVICE_PORT=9000 bash deploy/install.sh

# Docker：改 .env 中的 BACKEND_PORT / FRONTEND_PORT 后重新 up
```

**② 切换存储后端**

```bash
# 改用 Elasticsearch（需先部署 ES，至少 4G 内存）
STORAGE_BACKEND=elasticsearch
ES_URL=http://127.0.0.1:9200

# 改回 SQLite
STORAGE_BACKEND=sqlite
SQLITE_PATH=/opt/mini-siem/data/siem.db
```

切换后重启服务即可，历史数据不会自动迁移（SQLite 与 ES 各自独立存储）。

**③ 调整日志保留天数**：`ES_RETENTION_DAYS=30`（两种后端都生效，后台每小时清理一次过期日志，告警不会被清理）。

**④ 加固访问**：浏览器端必须使用管理员账号登录（JWT 会话，默认 12 小时过期），首次登录请立刻改掉 `admin123` 默认密码；把 `AGENT_TOKEN` 改成随机长字符串（或在「系统设置」页重新生成）；需要给脚本/第三方系统开放查询与上传接口时，再设置 `API_TOKEN` 作为静态 Bearer 令牌。

**⑤ 减少误报**：`IP_WHITELIST` 为**精确 IP 匹配**（不支持网段），例如 `IP_WHITELIST=127.0.0.1,::1,47.98.10.20`；若整片内网都不需要告警，直接设 `IGNORE_INTERNAL_SRC=true` 只关注外网攻击。规则级还可用 `suppression.ignore_ips` 单独豁免。

**⑥ 配置 GeoIP**：把 `GeoLite2-City.mmdb` 放进 `geoip/` 目录（裸机为 `/opt/mini-siem/geoip/`，Docker 为项目根目录 `./geoip/`），并把 `GEOIP_DB_PATH` 设为该文件的绝对路径，详见第八节。

### 7.4 日常运维命令

| 操作 | 裸机（systemd） | Docker Compose |
| --- | --- | --- |
| 查看状态 | `systemctl status mini-siem` | `docker compose ps` |
| 查看日志 | `journalctl -u mini-siem -f` | `docker compose logs -f backend` |
| 重启服务 | `systemctl restart mini-siem` | `docker compose restart backend` |
| 健康检查 | `curl http://127.0.0.1:8000/api/v1/health` | `curl http://127.0.0.1:8000/api/v1/health` |
| 升级版本 | 见下方「升级」 | 见下方「升级」 |

**升级（保留配置与数据）**

```bash
# 裸机：重跑安装脚本是幂等的，已存在的 .env 与 data/ 不会被覆盖
cd mini-siem && git pull
cd frontend && npm ci && npm run build && cd ..
sudo bash deploy/install.sh

# Docker
git pull && docker compose up -d --build
```

**备份与恢复（SQLite）**

```bash
# 备份：停服务后复制数据库文件（WAL 模式下 -wal/-shm 也要一起复制）
# system.db 保存管理员账号与后台配置，建议一并备份
sudo systemctl stop mini-siem
sudo cp /opt/mini-siem/data/siem.db* /root/siem-backup-$(date +%F)/
sudo cp /opt/mini-siem/data/system.db* /root/siem-backup-$(date +%F)/
sudo systemctl start mini-siem

# 恢复：把备份文件放回 data/ 目录后重启即可
```

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
| POST | `/api/v1/ingest/upload` | 上传文本日志或 `.evtx` 文件并解析入库（multipart，需登录 JWT 或 `API_TOKEN`） |
| POST | `/api/v1/auth/login` | 管理员登录，返回 JWT（默认 admin/admin123，首登强制改密） |
| GET | `/api/v1/auth/me` | 获取当前登录用户 |
| POST | `/api/v1/auth/change-password` | 修改自身密码 |
| GET | `/api/v1/admin/settings` | 读取可在线编辑的运行参数与只读部署信息 |
| PUT | `/api/v1/admin/settings` | 更新运行参数（降噪/GeoIP/日志级别/CORS 等） |
| POST | `/api/v1/admin/agent-token/regenerate` | 重新生成 Agent 采集令牌 |
| GET | `/api/v1/admin/system` | 系统运行信息（版本/Python/CPU/内存/磁盘/运行时长） |
| GET | `/api/v1/logs/search` | 多条件日志检索（全文/类型/主机/IP/等级/命中规则/时间） |
| GET | `/api/v1/logs/filters` | 获取筛选项（类型、主机、等级） |
| GET | `/api/v1/alerts` | 告警列表（状态/等级/规则/源IP/关键词/时间） |
| GET | `/api/v1/alerts/{id}` | 告警详情（含原始日志样本） |
| PATCH | `/api/v1/alerts/{id}` | 更新告警状态与备注 |
| POST | `/api/v1/alerts/bulk` | 批量更新告警状态 |
| GET | `/api/v1/rules` | 规则列表（含内置/自定义来源标识） |
| POST | `/api/v1/rules` | 新增自定义规则（管理员） |
| PUT | `/api/v1/rules/{id}` | 修改自定义规则（管理员，内置规则不可改） |
| DELETE | `/api/v1/rules/{id}` | 删除自定义规则（管理员，内置规则不可删） |
| PATCH | `/api/v1/rules/{id}` | 在线启停规则 / 调整等级与阈值 |
| POST | `/api/v1/rules/reload` | 重新加载规则文件 |
| POST | `/api/v1/rules/import-sigma` | 导入 Sigma 规则 YAML（管理员，支持多文档/覆盖选项） |
| GET | `/api/v1/stats/overview` | 总览指标与 TOP 排行 |
| GET | `/api/v1/stats/timeline` | 日志与告警时间趋势 |
| GET | `/api/v1/stats/geo` | 攻击地图数据 |
| GET | `/api/v1/stats/attackers` | 攻击源排行榜 |
| GET | `/api/v1/health` | 健康检查 |

## 十、目录结构

```
mini-siem/
├── docker-compose.yml            # 一键部署编排（ES 为可选 profile）
├── .env.example                  # 环境变量模板
├── deploy/
│   ├── install.sh                # 裸机一键部署脚本（低负载，systemd）
│   └── mini-siem.service         # systemd 单元文件
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── reset_admin.py           # 管理员密码重置工具
│   ├── rules/                    # 检测规则（挂载进容器，支持热加载）
│   │   ├── ssh_auth.yml
│   │   ├── web_attacks.yml
│   │   ├── windows_events.yml
│   │   └── custom_managed.yml    # 后台新增的自定义规则（运行后生成）
│   └── app/
│       ├── main.py               # 应用入口、后台维护任务、前端静态托管
│       ├── config.py             # 配置（存储后端开关等）
│       ├── state.py              # 全局单例容器
│       ├── api/                  # auth / admin / ingest / logs / alerts / rules / stats
│       ├── system/store.py       # 账号、密码哈希、JWT、系统配置存储
│       ├── normalize/
│       │   ├── parsers.py        # 各来源文本日志归一化解析
│       │   └── evtx_parser.py    # Windows .evtx 二进制解析
│       ├── engine/               # rule_loader / matcher / aggregator / pipeline / geoip
│       ├── models/schemas.py     # 数据模型
│       └── storage/              # 可插拔存储层
│           ├── sqlite_client.py  # SQLite 实现（默认，低负载）
│           └── es_client.py      # Elasticsearch 实现（可选）
├── frontend/                     # React 控制台（Vite + AntD + ECharts + Leaflet）
├── agent/                        # 采集 Agent（Linux/Windows 通用）
└── scripts/generate_demo_logs.py # 演示数据生成
```

## 十一、常见问题

**Elasticsearch 启动失败 / 容器反复重启**
先确认 `vm.max_map_count >= 262144`；内存不足时改用默认的 SQLite 后端（`STORAGE_BACKEND=sqlite`，不启用 es profile），或调小 `ES_HEAP`（如 `512m`）。

**日志进不来、日志检索为空**
1. 检查 Agent 日志中的报错，确认 `server.url` 与 `token` 正确；
2. `curl http://<服务器>:8000/api/v1/health`，确认返回 `"status":"ok"` 且 `"storage":true`（同时会显示当前 `backend` 是 sqlite 还是 elasticsearch）；
3. 日志只有在**新产生**时才会被采集，历史日志需用 `/ingest/raw` 或控制台「上传日志文件」导入。

**宿主机内存被占满 / 负载过高**
系统默认使用 SQLite + 单进程，正常只需 100~200MB 内存。若发现占用很高，通常是启用了 Elasticsearch（`docker compose --profile es`），执行 `docker compose --profile es down` 停掉并改用默认配置即可。

**SQLite 后端能撑多少数据**
单机建议日志总量控制在百万级以内；默认保留 30 天，可通过 `ES_RETENTION_DAYS` 调整。数据量继续增长时再切换 Elasticsearch 后端，接口完全一致、无需改代码。

**忘记管理员密码**
在服务器执行重置脚本（会自动读取部署目录 `.env` 定位系统库）：

```bash
cd /opt/mini-siem/backend
../venv/bin/python reset_admin.py            # 随机生成新密码并打印
../venv/bin/python reset_admin.py 新密码内容  # 或直接指定（至少 8 位）
```

Docker 部署可进入容器执行：`docker compose exec backend python reset_admin.py`。

**上传日志报 413 Request Entity Too Large**
上传文件超过大小上限。后端默认上限 200MB，可在「系统设置 → 文件上传」调大 `max_upload_mb`（立即生效），或在 `.env` 中设置 `MAX_UPLOAD_MB` 后重启。Docker 部署还有一层 nginx 限制（已配置为 500MB），**修改后需执行 `docker compose up -d --build frontend` 重建前端镜像生效**。超大 EVTX 建议在事件查看器中按时间/通道筛选导出，或分批上传。

**告警迟迟不出现**
频率类规则需要达到阈值（例如 SSH 暴力破解 300 秒内 5 次）；另外检查 `.env` 的 `MIN_ALERT_SEVERITY` 是否把低等级告警过滤掉了。

**攻击地图没有数据**
参考第八节配置 GeoIP；内网 IP 与保留地址不会解析，属正常现象。

**时间显示不对**
服务已设置 `TZ=Asia/Shanghai`（Docker 在 `docker-compose.yml` 中，裸机在 systemd 单元中），前端按浏览器本地时区展示。

## 十二、安全加固建议

1. 首次登录后立即修改默认密码 `admin123`；修改默认 `AGENT_TOKEN`；仅在确有第三方系统对接需要时设置 `API_TOKEN`。
2. 生产环境请前置 HTTPS（裸机部署可用 Nginx 或 Caddy 反代 8000 端口），或只通过内网/VPN 暴露控制台端口。
3. 若启用了 Elasticsearch，其端口已在编排中限制为 `127.0.0.1` 访问，请勿改为 `0.0.0.0`。
4. 远程 Agent 上报建议走内网或专用通道，避免令牌在公网明文传输。
5. 定期检查 `ES_RETENTION_DAYS`、磁盘水位以及数据库文件大小（默认 `data/siem.db`，另有 `siem.db-wal`），避免磁盘写满导致写入失败。

## 十三、停止与卸载

**裸机部署（systemd）**

```bash
sudo systemctl stop mini-siem        # 停止服务
sudo systemctl disable mini-siem     # 取消开机自启
sudo rm -rf /opt/mini-siem           # 删除程序与数据库（数据不可恢复）
sudo rm -f /etc/systemd/system/mini-siem.service && sudo systemctl daemon-reload
sudo userdel minisiem
```

**Docker Compose**

```bash
docker compose down                 # 停止服务（保留数据）
docker compose --profile es down    # 若启用过 es profile，需带上该参数
docker compose down -v              # 停止并删除数据卷（清空所有日志与告警）
```
