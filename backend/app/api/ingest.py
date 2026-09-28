"""日志上报接口：供采集 Agent、第三方脚本推送日志，以及后台上传日志文件解析。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile

from app.api.utils import require_agent_token, require_api_token
from app.models.schemas import (
    IngestEvent,
    IngestRequest,
    IngestResponse,
    UploadPreviewItem,
    UploadResult,
)
from app.normalize.parsers import build_event, guess_source_type
from app.state import state
from app.normalize.evtx_parser import is_evtx_content, parse_evtx

router = APIRouter(prefix="/ingest", tags=["采集"])

MAX_EVENTS_PER_REQUEST = 2000
# 单文件上传上限 50MB、单文件最多解析 20 万行，避免超大文件拖垮服务
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_UPLOAD_LINES = 200_000
UPLOAD_CHUNK = 1024 * 1024
UPLOAD_BATCH = 1000
PREVIEW_SIZE = 5
VALID_SOURCE_TYPES = {"auto", "nginx", "apache", "ssh", "linux", "windows", "syslog", "unknown"}


@router.post("", response_model=IngestResponse, summary="批量上报日志")
async def ingest_batch(
    payload: IngestRequest, _: None = Depends(require_agent_token)
) -> IngestResponse:
    """接收 Agent 上报的一批日志事件并送入检测管道。"""
    events = payload.events[:MAX_EVENTS_PER_REQUEST]
    return await state.pipeline.process(payload.host, payload.source_type, events)


@router.post("/raw", response_model=IngestResponse, summary="上报原始文本日志")
async def ingest_raw(
    request: Request,
    host: str = Query(default="unknown", description="日志来源主机名"),
    source_type: str = Query(default="syslog", description="日志类型: nginx/apache/ssh/windows/syslog"),
    _: None = Depends(require_agent_token),
) -> IngestResponse:
    """接收纯文本日志（每行一条），便于用 curl / rsyslog 快速接入。"""
    body = (await request.body()).decode("utf-8", errors="ignore")
    events = [IngestEvent(raw=line) for line in body.splitlines() if line.strip()]
    return await state.pipeline.process(host, source_type, events)


async def _read_upload(file: UploadFile) -> bytes:
    """分块读取上传文件，超过大小上限时抛出 413。"""
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = await file.read(UPLOAD_CHUNK)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"文件超过 {MAX_UPLOAD_BYTES // 1024 // 1024}MB 上限，请先按天切分后再上传",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _decode_text(raw: bytes) -> str:
    """把文件内容解码成文本，自动兼容 UTF-16（带 BOM）与 GBK 编码。"""
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="ignore")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    for encoding in ("utf-8", "gbk"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="ignore")


def _build_preview(host: str, source_type: str, events: list[IngestEvent]) -> list[UploadPreviewItem]:
    """对前若干条事件做解析预览，并标注命中的规则 ID。"""
    preview: list[UploadPreviewItem] = []
    for item in events[:PREVIEW_SIZE]:
        event = build_event(host, source_type, item.raw, item.fields)
        if item.timestamp:
            event.timestamp = item.timestamp
        hits = state.engine.evaluate(event)
        preview.append(
            UploadPreviewItem(
                timestamp=event.timestamp,
                src_ip=event.src_ip,
                user=event.user,
                level=event.level,
                message=(event.url or event.message or item.raw)[:200],
                matched=[hit.rule.id for hit in hits],
            )
        )
    return preview


async def _process_events(host: str, source_type: str, events: list[IngestEvent]) -> tuple[int, int]:
    """分批把解析出的事件送入检测管道，返回 (入库数, 新增告警数)。"""
    accepted = 0
    alerts = 0
    for index in range(0, len(events), UPLOAD_BATCH):
        result = await state.pipeline.process(host, source_type, events[index : index + UPLOAD_BATCH])
        accepted += result.accepted
        alerts += result.alerts
    return accepted, alerts


@router.post("/upload", response_model=UploadResult, summary="上传日志文件并解析")
async def upload_log_file(
    file: UploadFile = File(..., description="文本日志或 Windows .evtx 事件日志文件"),
    host: str = Form(default="upload", description="日志来源主机名"),
    source_type: str = Form(default="auto", description="日志类型，auto 表示自动识别"),
    _: None = Depends(require_api_token),
) -> UploadResult:
    """接收上传的日志文件，按类型解析后送入检测管道，返回解析统计与结果预览。

    支持两类输入：
    1. 文本日志（Nginx/Apache/SSH/Syslog 等），按行解析；
    2. Windows 事件日志 .evtx 二进制文件，跨平台解析为结构化事件后按 Windows 规则检测。
    """
    if source_type not in VALID_SOURCE_TYPES:
        raise HTTPException(status_code=400, detail=f"不支持的日志类型: {source_type}")

    raw = await _read_upload(file)
    if not raw:
        raise HTTPException(status_code=400, detail="文件内容为空")

    filename = file.filename or "upload.log"

    # ---------------- EVTX 分支：Windows 事件日志二进制 ----------------
    if filename.lower().endswith(".evtx") or is_evtx_content(raw):
        if source_type not in ("auto", "windows"):
            raise HTTPException(status_code=400, detail="EVTX 文件的日志类型必须为 windows（或 auto）")
        try:
            parsed_events, skipped = parse_evtx(raw, MAX_UPLOAD_LINES)
        except ImportError as exc:
            raise HTTPException(status_code=500, detail="服务端缺少 python-evtx 依赖，无法解析 EVTX 文件") from exc
        except Exception as exc:  # 文件整体无法识别时给出明确提示
            raise HTTPException(status_code=400, detail=f"EVTX 文件解析失败：{exc}") from exc

        events = [
            IngestEvent(raw=item["raw"], fields=item["fields"], timestamp=item["timestamp"])
            for item in parsed_events
        ]
        accepted, alerts = await _process_events(host, "windows", events)
        return UploadResult(
            filename=filename,
            source_type="windows",
            auto_detected=True,
            total_lines=len(events) + skipped,
            accepted=accepted,
            skipped=skipped,
            alerts=alerts,
            preview=_build_preview(host, "windows", events),
        )

    # ---------------- 文本日志分支 ----------------
    text = _decode_text(raw)
    if "\x00" in text[:4000]:
        raise HTTPException(
            status_code=400,
            detail="检测到不支持的二进制文件（仅支持文本日志与 Windows .evtx 事件日志）",
        )

    all_lines = text.splitlines()
    lines = [line.strip() for line in all_lines if line.strip()]
    if not lines:
        raise HTTPException(status_code=400, detail="文件中没有有效的日志行")

    auto_detected = source_type == "auto"
    resolved_type = guess_source_type(filename, text) if auto_detected else source_type
    if resolved_type == "unknown":
        resolved_type = "syslog"  # 无法识别时按通用 syslog 处理，解析器会自动尝试访问日志格式

    processed = lines[:MAX_UPLOAD_LINES]
    events = [IngestEvent(raw=line) for line in processed]
    accepted, alerts = await _process_events(host, resolved_type, events)

    return UploadResult(
        filename=filename,
        source_type=resolved_type,
        auto_detected=auto_detected,
        total_lines=len(all_lines),
        accepted=accepted,
        skipped=len(all_lines) - len(processed),
        alerts=alerts,
        preview=_build_preview(host, resolved_type, events),
    )
