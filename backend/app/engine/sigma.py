"""Sigma 规则（YAML）到内部检测规则的转换器。

支持 Sigma 规范的常用子集：
- detection 块的 selection/filter 命名与 ``condition`` 表达式（and/or/not、括号、
  ``1/all of them``、``1/all of selection*`` 通配）；
- 字段修饰符：contains(|all)、startswith、endswith、re、base64/base64offset、
  windash、gt/gte/lt/lte、nocase（引擎本身大小写不敏感，自动忽略）；
- logsource 到内部日志类型的映射、level 到 severity 的映射、字段名映射；
- 列表型 selection（组内 AND、组间 OR）与 OR 条件自动拆分为多条内部规则。

内部规则模型为“all_of 全满足 AND any_of 任一满足”的两层结构，无法表达任意
布尔表达式，因此转换器先把 condition 化为析取范式（DNF），每个合取项生成一条
内部规则（OR 的每个分支一条）。

暂不支持（对应规则会被标记为 error 并跳过，不会静默放宽）：
- 聚合/近邻表达式（``| count(...) ...``、``near ...``）——可在后台用阈值规则手动创建；
- cidr、null、expand 等修饰符；
- “N 选 M”量化（仅支持 1/all）。
"""
from __future__ import annotations

import base64
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from app.models.schemas import Rule, RuleCondition

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 字段映射：Sigma 字段名（小写） -> 归一化 LogEvent 字段
# ---------------------------------------------------------------------------
SIGMA_FIELD_MAP: dict[str, str] = {
    # Windows 事件通用
    "eventid": "event_id",
    "eventcode": "event_id",
    "eventtype": "event_id",
    "eventrecordid": "raw",
    "channel": "channel",
    "logname": "channel",
    "computername": "host",
    "workstationname": "host",
    # 账号
    "subjectusername": "user",
    "targetusername": "user",
    "newtargetusername": "user",
    "membername": "user",
    "accountname": "user",
    "clientusername": "user",
    "user": "user",
    "username": "user",
    "cs-username": "user",
    # 网络
    "ipaddress": "src_ip",
    "clientaddress": "src_ip",
    "sourcenetworkaddress": "src_ip",
    "sourceaddress": "src_ip",
    "sourceip": "src_ip",
    "src_ip": "src_ip",
    "c-ip": "src_ip",
    "ip": "src_ip",
    "destaddress": "dst_ip",
    "destinationip": "dst_ip",
    "destinationhostname": "host",
    # 进程/服务
    "newprocessname": "process",
    "imagepath": "process",
    "processname": "process",
    "image": "process",
    "parentimage": "process",
    "parentprocessname": "process",
    "servicefilename": "process",
    "servicename": "process",
    "newservice": "process",
    "processcommandline": "command",
    "commandline": "command",
    "parentcommandline": "command",
    "servicestartname": "command",
    # Web 访问日志
    "method": "method",
    "requestmethod": "method",
    "cs-method": "method",
    "uri": "url",
    "url": "url",
    "requesturi": "url",
    "c-uri": "url",
    "c-uri-stem": "path",
    "status": "status_code",
    "statuscode": "status_code",
    "sc-status": "status_code",
    "useragent": "user_agent",
    "http_user_agent": "user_agent",
    "c-useragent": "user_agent",
    "cs-user-agent": "user_agent",
}

# Sigma level -> 内部 severity
SIGMA_LEVEL_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "noteworthy": "medium",
    "warning": "medium",
    "low": "low",
    "informational": "low",
    "info": "low",
}

# 可识别的修饰符（其中 utf16/wide/ascii 仅作降级提示）
_KNOWN_MODIFIERS = {
    "contains", "all", "startswith", "endswith", "re", "base64", "base64offset",
    "windash", "gt", "gte", "lt", "lte", "nocase",
    "utf16le", "utf16be", "utf16", "wide", "ascii",
}
# 明确不支持、需要报错的修饰符
_UNSUPPORTED_MODIFIERS = {"cidr", "null", "expand", "gt_field", "lt_field"}


@dataclass
class SigmaItemResult:
    """单条 Sigma 文档的转换结果。"""

    title: str
    sigma_id: str = ""
    rule_ids: list[str] = field(default_factory=list)
    severity: str = "medium"
    warnings: list[str] = field(default_factory=list)
    status: str = "ready"  # ready / error
    error: str = ""


@dataclass
class SigmaConvertResult:
    """整份 YAML（可能含多条文档）的转换结果。"""

    rules: list[Rule] = field(default_factory=list)
    items: list[SigmaItemResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _slugify_id(sigma_id: str, title: str) -> str:
    """根据 Sigma UUID/标题生成符合内部 ID 规范（小写字母数字）的规则 ID 前缀。"""
    hexpart = re.sub(r"[^a-z0-9]", "", str(sigma_id or "").lower())
    digest = hexpart[:12] if hexpart else hashlib.md5(title.encode("utf-8")).hexdigest()[:12]
    return f"sigma-{digest}"


def _map_field(field_name: str) -> tuple[str, str | None]:
    """把 Sigma 字段名映射为内部字段，返回 (内部字段, 降级警告或 None)。"""
    name = field_name.strip().lower()
    if "\\" in name:  # 形如 SubjectDomainName\\SubjectUserName，取最后一段
        name = name.rsplit("\\", 1)[1]
    mapped = SIGMA_FIELD_MAP.get(name)
    if mapped:
        return mapped, None
    return "raw", f"未识别字段「{field_name}」，已降级为 raw 全文匹配"


def _as_list(value: Any) -> list[Any]:
    """标量包装为单元素列表，列表原样返回。"""
    return value if isinstance(value, list) else [value]


def _b64_variants(text: str) -> list[str]:
    """生成字符串的 base64 三偏移变体（同时覆盖 UTF-8 与 UTF-16LE，Windows 命令行常见）。"""
    variants: list[str] = []
    for raw in (text.encode("utf-8"), text.encode("utf-16le")):
        variants.append(base64.b64encode(raw).decode("ascii"))
        variants.append(base64.b64encode(b"\x00" + raw).decode("ascii")[2:])
        variants.append(base64.b64encode(b"\x00\x00" + raw).decode("ascii")[4:])
    return list(dict.fromkeys(v for v in variants if len(v) >= 4))


def _windash_pattern(text: str) -> str:
    """把命令行参数值转成同时匹配 - 与 / 前缀的正则片段，如 -enc -> [-/]enc。"""
    escaped = re.escape(text)
    return "[-/]" + escaped[1:] if text.startswith("-") else escaped


def _join_regex(patterns: list[str]) -> str:
    """把多个子串匹配模式合并为一个 OR 正则。"""
    return "(?:" + "|".join(patterns) + ")"


def _stringify(value: Any) -> str:
    """把 Sigma 标量值转成字符串（布尔/数字统一口径与引擎 str() 比较一致）。"""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


# ---------------------------------------------------------------------------
# 单个字段条件转换
# ---------------------------------------------------------------------------

def _convert_field(
    key: str,
    value: Any,
    negated: bool,
    warnings: list[str],
) -> tuple[list[RuleCondition], list[str]]:
    """转换 detection 块中的一个键值对，返回 (条件列表, 错误列表)。

    块内多个键为 AND；单个键的列表值默认 OR（contains|all 时为 AND）。
    """
    raw_field, *modifier_list = key.split("|")
    mods = {m.strip().lower() for m in modifier_list if m.strip()}
    field_name, warn = _map_field(raw_field)
    if warn:
        warnings.append(warn)

    unsupported = mods & _UNSUPPORTED_MODIFIERS
    if unsupported:
        return [], [f"字段「{raw_field}」使用了暂不支持的修饰符：{', '.join(sorted(unsupported))}"]
    unknown = mods - _KNOWN_MODIFIERS
    if unknown:
        return [], [f"字段「{raw_field}」使用了未知修饰符：{', '.join(sorted(unknown))}"]
    if mods & {"utf16le", "utf16be", "utf16", "wide", "ascii"}:
        warnings.append(f"字段「{raw_field}」的编码修饰符已按明文匹配近似处理")

    values = _as_list(value)

    # 1) 数值比较
    if mods & {"gt", "gte", "lt", "lte"}:
        conditions: list[RuleCondition] = []
        for item in values:
            try:
                num = float(item)
            except (TypeError, ValueError):
                return [], [f"字段「{raw_field}」的数值比较值非法：{item}"]
            if mods & {"gt", "gte"}:
                conditions.append(RuleCondition(field=field_name, gt=num))
            else:
                conditions.append(RuleCondition(field=field_name, lt=num))
        return conditions, []

    is_regex_kind = bool(mods & {"re", "startswith", "endswith", "base64", "base64offset"})
    is_contains = "contains" in mods or "base64" in mods or "base64offset" in mods
    all_required = "all" in mods

    # 2) 裸等值（无任何匹配类修饰符；单独 windash 按正则处理）
    if not is_regex_kind and not is_contains and "windash" not in mods:
        if negated:
            return [RuleCondition(field=field_name, not_in=list(values))], []
        if len(values) == 1:
            return [RuleCondition(field=field_name, equals=values[0])], []
        return [RuleCondition(field=field_name, **{"in": list(values)})], []

    # 3) 匹配类：先收集“子串模式”，OR 合并为单条 regex；AND 语义拆成多条 contains
    regex_patterns: list[str] = []
    and_contains: list[str] = []
    # 普通 contains（不带 windash/re 等）子串：单值优先用 contains 算子，便于在界面阅读
    plain_contains: list[str] = []
    for item in values:
        text_value = _stringify(item)
        if "re" in mods:
            regex_patterns.append(text_value)
        elif "startswith" in mods:
            regex_patterns.append("^" + re.escape(text_value))
        elif "endswith" in mods:
            regex_patterns.append(re.escape(text_value) + "$")
        elif "base64" in mods or "base64offset" in mods:
            regex_patterns.extend(re.escape(v) for v in _b64_variants(text_value))
            if "base64offset" not in mods:
                warnings.append(f"字段「{raw_field}」的 base64 匹配已按 UTF-8/UTF-16LE 三偏移展开")
        elif "windash" in mods:
            regex_patterns.append(_windash_pattern(text_value))
        elif all_required:
            and_contains.append(text_value)
        else:
            plain_contains.append(text_value)

    # 单个普通 contains 子串直接保留为 contains 算子；多个值（OR 语义）合并进 regex
    if len(plain_contains) == 1 and not regex_patterns:
        single_contains = plain_contains[0]
    else:
        single_contains = None
        if plain_contains:
            regex_patterns.extend(re.escape(text_value) for text_value in plain_contains)

    result: list[RuleCondition] = []
    if single_contains is not None:
        if negated:
            result.append(RuleCondition(field=field_name, not_contains=single_contains))
        else:
            result.append(RuleCondition(field=field_name, contains=single_contains))
    elif regex_patterns:
        if negated:
            # 否定正则：拆成对每个去锚转子串的 not_contains（近似）
            warnings.append(f"字段「{raw_field}」的否定正则已近似为多个“不包含”条件")
            for pattern in regex_patterns:
                plain = re.sub(r"\\(.)", r"\1", pattern).lstrip("^").rstrip("$")
                if plain and not plain.startswith("(?:"):
                    result.append(RuleCondition(field=field_name, not_contains=plain))
        else:
            result.append(RuleCondition(field=field_name, regex=_join_regex(regex_patterns)))

    for text_value in and_contains:
        if negated:
            # NOT(全部包含) 无法用 AND 条件精确表达，保守地排除第一个子串
            warnings.append(f"字段「{raw_field}」的否定 contains|all 已近似为排除第一个子串")
            result.append(RuleCondition(field=field_name, not_contains=text_value))
        else:
            result.append(RuleCondition(field=field_name, contains=text_value))

    return result, []


# ---------------------------------------------------------------------------
# detection 块转换
# ---------------------------------------------------------------------------

def _convert_block(
    block: dict[str, Any],
    negated: bool,
    item_result: SigmaItemResult,
) -> tuple[list[RuleCondition], list[str]]:
    """把一个 selection/filter 块（dict 形态）转换为 AND 条件列表。"""
    conditions: list[RuleCondition] = []
    errors: list[str] = []
    for key, value_raw in block.items():
        conds, key_errors = _convert_field(str(key), value_raw, negated, item_result.warnings)
        conditions.extend(conds)
        errors.extend(key_errors)
    if negated and conditions:
        # filter 块按字段逐项排除（比严格的 NOT(A and B) 更保守、更贴合 Sigma 使用惯例）
        item_result.warnings.append("含排除条件（not filter），已按字段逐项排除近似转换")
    return conditions, errors


# ---------------------------------------------------------------------------
# condition 表达式解析（递归下降），list 型块在引用时展开为 OR 合成叶子
# ---------------------------------------------------------------------------

@dataclass
class _Token:
    kind: str  # and/or/not/lparen/rparen/name
    value: str = ""


_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")
_SYNTH_SEP = "#"


def _tokenize_condition(condition: str) -> list[_Token]:
    """把 condition 字符串切分为记号流。"""
    tokens: list[_Token] = []
    for raw in _TOKEN_RE.findall(condition):
        low = raw.lower()
        if raw == "(":
            tokens.append(_Token("lparen"))
        elif raw == ")":
            tokens.append(_Token("rparen"))
        elif low == "and":
            tokens.append(_Token("and"))
        elif low == "or":
            tokens.append(_Token("or"))
        elif low == "not":
            tokens.append(_Token("not"))
        else:
            tokens.append(_Token("name", raw.lstrip("$")))
    return tokens


def _expand_ref(name: str, flat_blocks: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """把块引用展开为 AST 叶子；列表型块（组内 AND、组间 OR）展开为 OR 节点。"""
    leaf: dict[str, Any] = {"op": "leaf", "name": name, "negated": False}
    if not name.startswith("__list"):
        return leaf
    members = sorted(k for k in flat_blocks if k.startswith(name + _SYNTH_SEP))
    node: dict[str, Any] = {"op": "leaf", "name": members[0], "negated": False}
    for extra in members[1:]:
        node = {"op": "or", "children": [node, {"op": "leaf", "name": extra, "negated": False}]}
    return node


class _ConditionParser:
    """解析 Sigma condition 为 AST，叶子引用展开后的合成块名。"""

    def __init__(self, tokens: list[_Token], block_names: set[str], flat_blocks: dict[str, dict[str, Any]]) -> None:
        """记录记号流、原始块名与展开后的合成块。"""
        self.tokens = tokens
        self.pos = 0
        self.block_names = block_names
        self.flat_blocks = flat_blocks

    def _peek(self) -> _Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> _Token:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self) -> dict[str, Any]:
        """解析完整表达式。"""
        node = self._parse_or()
        if self.pos != len(self.tokens):
            raise ValueError(f"condition 存在无法解析的片段：{self._peek() and self._peek().value}")
        return node

    def _parse_or(self) -> dict[str, Any]:
        node = self._parse_and()
        while self._peek() and self._peek().kind == "or":
            self._next()
            node = {"op": "or", "children": [node, self._parse_and()]}
        return node

    def _parse_and(self) -> dict[str, Any]:
        node = self._parse_unary()
        while self._peek() and self._peek().kind == "and":
            self._next()
            node = {"op": "and", "children": [node, self._parse_unary()]}
        return node

    def _parse_unary(self) -> dict[str, Any]:
        if self._peek() and self._peek().kind == "not":
            self._next()
            return {"op": "not", "children": [self._parse_unary()]}
        return self._parse_primary()

    def _parse_primary(self) -> dict[str, Any]:
        token = self._peek()
        if token is None:
            raise ValueError("condition 不完整")
        if token.kind == "lparen":
            self._next()
            node = self._parse_or()
            if not self._next() or self.tokens[self.pos - 1].kind != "rparen":
                raise ValueError("condition 缺少右括号")
            return node
        if token.kind != "name":
            raise ValueError(f"condition 存在非法记号：{token.value}")
        self._next()

        # 量化表达式：1/all of them|pattern|(a,b)
        if self._peek() and self._peek().kind == "name" and self._peek().value.lower() == "of":
            self._next()
            target = self._next().value
            return self._build_quantifier(token.value.lower(), target)

        name = token.value
        if name not in self.block_names:
            raise ValueError(f"condition 引用了不存在的 detection 块：{name}")
        return _expand_ref(self._flat_name(name), self.flat_blocks)

    def _flat_name(self, original: str) -> str:
        """返回原始块名对应的合成名（dict 型同名，list 型为 __list 前缀）。"""
        return original if original in self.flat_blocks else f"__list{original}"

    def _all_flat_refs(self, original_names: list[str]) -> list[str]:
        """把原始块名列表展开为全部合成叶子名。"""
        refs: list[str] = []
        for name in original_names:
            flat = self._flat_name(name)
            if flat in self.flat_blocks:
                refs.append(flat)
            else:
                refs.extend(sorted(k for k in self.flat_blocks if k.startswith(flat + _SYNTH_SEP)))
        return refs

    def _build_quantifier(self, wanted: str, target: str) -> dict[str, Any]:
        """处理 1/all of them|pattern|(a,b) 形式。"""
        if target == "them":
            names = sorted(self.block_names)
        elif "*" in target or "?" in target:
            pattern = re.compile("^" + re.escape(target).replace(r"\*", ".*").replace(r"\?", ".") + "$")
            names = sorted(n for n in self.block_names if pattern.match(n))
            # 消费可能残留的右括号前记号（通配形式一般没有）
        else:
            names = [target.lstrip("$")]
            while self._peek() and self._peek().kind == "name":
                names.append(self._next().value.lstrip("$"))
        refs = self._all_flat_refs(names)
        if not refs:
            raise ValueError(f"量化表达式没有匹配到任何 detection 块：{wanted} of {target}")
        combinator = "and" if wanted == "all" else "or" if wanted == "1" else None
        if combinator is None:
            raise ValueError(f"暂不支持“N 选 M”量化表达式：{wanted} of {target}（仅支持 1/all）")
        node: dict[str, Any] = {"op": "leaf", "name": refs[0], "negated": False}
        for extra in refs[1:]:
            node = {"op": combinator, "children": [node, {"op": "leaf", "name": extra, "negated": False}]}
        return node


def _nnf(node: dict[str, Any], negated: bool = False) -> dict[str, Any]:
    """把 AST 化为否定范式（NOT 只出现在叶子）。"""
    op = node["op"]
    if op == "leaf":
        return {"op": "leaf", "name": node["name"], "negated": negated ^ node.get("negated", False)}
    if op == "not":
        return _nnf(node["children"][0], not negated)
    if negated:
        flipped = "and" if op == "or" else "or"
        return {"op": flipped, "children": [_nnf(child, True) for child in node["children"]]}
    return {"op": op, "children": [_nnf(child) for child in node["children"]]}


def _dnf(node: dict[str, Any]) -> list[list[dict[str, Any]]]:
    """把 NNF 展开为析取范式：返回若干合取项，每项为叶子列表。"""
    if node["op"] == "leaf":
        return [[node]]
    children_terms = [_dnf(child) for child in node["children"]]
    if node["op"] == "or":
        return [term for group in children_terms for term in group]
    # AND：笛卡尔积
    result: list[list[dict[str, Any]]] = [[]]
    for group in children_terms:
        result = [base + term for base in result for term in group]
    return result


# ---------------------------------------------------------------------------
# logsource 映射
# ---------------------------------------------------------------------------

def _map_log_types(logsource: dict[str, Any] | None, warnings: list[str]) -> list[str]:
    """根据 Sigma logsource 判断内部日志类型范围。"""
    if not isinstance(logsource, dict):
        return ["any"]
    product = str(logsource.get("product", "")).lower()
    service = str(logsource.get("service", "")).lower()
    category = str(logsource.get("category", "")).lower()
    if product == "windows":
        return ["windows"]
    if service in {"nginx", "apache"}:
        return [service]
    if product == "webserver" or category in {"webserver", "proxy"}:
        return ["nginx", "apache"]
    if service == "ssh" or category == "ssh":
        return ["ssh"]
    if product in {"linux", "unix"} or service in {"syslog", "auth", "kern"}:
        return ["linux", "syslog", "ssh"]
    warnings.append(
        f"logsource（product={product or '-'}, service={service or '-'}）无精确映射，规则将对全部日志类型生效"
    )
    return ["any"]


# ---------------------------------------------------------------------------
# 单文档 / 多文档转换
# ---------------------------------------------------------------------------

def _flatten_blocks(detection: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """把 detection 块展开为 合成名 -> dict 组 的扁平表。

    dict 型块保持原名；list 型块（组内 AND、组间 OR）展开为 ``__list<名>#序号``。
    """
    flat: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for name, spec in detection.items():
        if name == "condition":
            continue
        groups = spec if isinstance(spec, list) else [spec]
        if isinstance(spec, list):
            for index, group in enumerate(groups):
                if not isinstance(group, dict):
                    errors.append(f"块 {name}[{index}] 不是键值表结构")
                    continue
                flat[f"__list{name}{_SYNTH_SEP}{index}"] = group
        elif isinstance(spec, dict):
            flat[name] = spec
        else:
            errors.append(f"块 {name} 既不是键值表也不是键值表列表")
    return flat, errors


def _convert_document(doc: dict[str, Any]) -> SigmaConvertResult:
    """转换单条 Sigma 规则文档（可能展开为多条内部规则）。"""
    result = SigmaConvertResult()
    item = SigmaItemResult(title=str(doc.get("title") or "未命名 Sigma 规则"), sigma_id=str(doc.get("id") or ""))
    result.items.append(item)

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        item.status = "error"
        item.error = "缺少 detection 定义"
        return result
    condition_text = detection.get("condition")
    if isinstance(condition_text, list):
        condition_text = condition_text[0]  # 多 condition（时间关联）取第一个
    if not isinstance(condition_text, str) or not condition_text.strip():
        item.status = "error"
        item.error = "缺少 condition 表达式"
        return result
    if "|" in condition_text or re.search(r"\bnear\b", condition_text, re.IGNORECASE):
        item.status = "error"
        item.error = "暂不支持聚合/近邻条件（count/near），可在规则管理页用“阈值统计”类型手动创建"
        return result

    block_names = {k for k in detection if k != "condition"}
    if not block_names:
        item.status = "error"
        item.error = "detection 中没有任何 selection/filter 块"
        return result

    flat_blocks, flat_errors = _flatten_blocks(detection)
    if flat_errors:
        item.status = "error"
        item.error = "；".join(flat_errors)
        return result

    try:
        tokens = _tokenize_condition(condition_text)
        ast = _ConditionParser(tokens, block_names, flat_blocks).parse()
        terms = _dnf(_nnf(ast))
    except ValueError as exc:
        item.status = "error"
        item.error = f"condition 解析失败：{exc}"
        return result

    if len(terms) > 16:
        item.status = "error"
        item.error = f"条件组合展开后达 {len(terms)} 条规则，过于复杂（上限 16），请拆分为多个 Sigma 规则"
        return result

    log_types = _map_log_types(doc.get("logsource"), item.warnings)
    severity = SIGMA_LEVEL_MAP.get(str(doc.get("level", "medium")).lower(), "medium")
    item.severity = severity
    base_id = _slugify_id(item.sigma_id, item.title)
    tags = [str(tag) for tag in doc.get("tags", []) if isinstance(tag, str)]
    if "sigma" not in tags:
        tags.append("sigma")
    description = str(doc.get("description") or item.title)[:500]
    name = item.title[:100]
    multi = len(terms) > 1

    for index, leaves in enumerate(terms, start=1):
        conditions: list[RuleCondition] = []
        errors: list[str] = []
        for leaf in leaves:
            group = flat_blocks.get(leaf["name"])
            if group is None:
                continue
            conds, block_errors = _convert_block(group, leaf["negated"], item)
            conditions.extend(conds)
            errors.extend(block_errors)
        if errors:
            item.status = "error"
            item.error = "；".join(dict.fromkeys(errors))
            return result
        if not conditions:
            item.status = "error"
            item.error = "转换后没有任何有效匹配条件"
            return result
        rule_id = (base_id if not multi else f"{base_id}-{index}")[:64]
        rule = Rule(
            id=rule_id,
            name=name if not multi else f"{name}（{index}/{len(terms)}）",
            description=description,
            severity=severity,  # type: ignore[arg-type]
            type="match",
            enabled=True,
            log_types=log_types,
            tags=tags,
            all_of=conditions,
        )
        result.rules.append(rule)
        item.rule_ids.append(rule_id)

    if multi:
        item.warnings.append(f"condition 含 OR 组合，已拆分为 {len(terms)} 条等价规则")
    return result


def convert_sigma_content(content: str) -> SigmaConvertResult:
    """解析 Sigma YAML 文本（支持 ``---`` 多文档）并转换为内部规则。"""
    result = SigmaConvertResult()
    try:
        documents = list(yaml.safe_load_all(content))
    except yaml.YAMLError as exc:
        result.items.append(SigmaItemResult(title="（YAML 解析失败）", status="error", error=f"YAML 语法错误：{exc}"))
        return result

    for doc in documents:
        if doc is None:
            continue
        if not isinstance(doc, dict):
            result.items.append(
                SigmaItemResult(title="（非键值表文档）", status="error", error="每条 Sigma 规则必须是 YAML 键值表")
            )
            continue
        part = _convert_document(doc)
        result.rules.extend(part.rules)
        result.items.extend(part.items)
    return result
