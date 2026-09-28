"""规则加载器：从 YAML 文件加载检测规则，支持热加载与在线开关。"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from app.models.schemas import Rule, RuleCondition, Severity, ThresholdConfig

logger = logging.getLogger(__name__)

OVERRIDE_FILE = "_overrides.json"
# 后台新增/编辑的自定义规则统一保存在该文件，与内置规则文件隔离
MANAGED_FILE = "custom_managed.yml"


class RuleLoader:
    """负责扫描规则目录、解析 YAML 并维护运行期覆盖配置。"""

    def __init__(self, rules_dir: str) -> None:
        """记录规则目录并加载已保存的覆盖配置。"""
        self.rules_dir = Path(rules_dir)
        self.rules: list[Rule] = []
        self.overrides: dict[str, dict[str, Any]] = self._load_overrides()
        # 后台管理的自定义规则 ID 集合，由自定义规则文件内容填充
        self.managed_ids: set[str] = set()
        self._signature: dict[str, float] = {}

    # ---------------- 加载 ----------------

    def _load_overrides(self) -> dict[str, dict[str, Any]]:
        """读取持久化的规则覆盖配置（开关/等级/阈值）。"""
        path = self.rules_dir / OVERRIDE_FILE
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.warning("规则覆盖配置解析失败，已忽略: %s", path)
            return {}

    def _save_overrides(self) -> None:
        """把覆盖配置写回磁盘，保证重启后依然生效。"""
        path = self.rules_dir / OVERRIDE_FILE
        path.write_text(json.dumps(self.overrides, ensure_ascii=False, indent=2), encoding="utf-8")

    def load(self) -> list[Rule]:
        """重新扫描目录并加载全部规则，返回规则列表。"""
        rules: list[Rule] = []
        if not self.rules_dir.exists():
            logger.warning("规则目录不存在: %s", self.rules_dir)
            return rules

        self.managed_ids = set(self._read_managed_ids())
        for path in sorted(self.rules_dir.glob("*.y*ml")):
            for raw in self._read_rule_file(path):
                rule = self._build_rule(raw, path)
                if rule:
                    rules.append(rule)

        self.rules = rules
        logger.info("已加载 %s 条检测规则", len(rules))
        return rules

    def _read_rule_file(self, path: Path) -> list[dict[str, Any]]:
        """读取单个规则文件，支持一个文件包含多条规则。"""
        try:
            content = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as exc:
            logger.error("规则文件解析失败 %s: %s", path.name, exc)
            return []
        if isinstance(content, dict) and "rules" in content:
            return list(content["rules"])
        if isinstance(content, dict):
            return [content]
        if isinstance(content, list):
            return content
        return []

    def _build_rule(self, raw: dict[str, Any], path: Path) -> Rule | None:
        """把 YAML 字典转换为 Rule 对象，并应用覆盖配置。"""
        if not isinstance(raw, dict) or "id" not in raw:
            logger.warning("跳过无效规则（缺少 id）: %s", path.name)
            return None
        try:
            rule = Rule(**normalize_rule_dict(raw))
        except Exception as exc:  # 单条规则异常不影响其他规则加载
            logger.error("规则 %s 校验失败: %s", raw.get("id"), exc)
            return None

        override = self.overrides.get(rule.id)
        if override:
            if "enabled" in override:
                rule.enabled = bool(override["enabled"])
            if override.get("severity"):
                rule.severity = override["severity"]
            if override.get("threshold"):
                rule.threshold = ThresholdConfig(**override["threshold"])
        return rule

    # ---------------- 运行期调整 ----------------

    def update(self, rule_id: str, enabled: bool | None, severity: Severity | None,
               threshold: ThresholdConfig | None) -> Rule | None:
        """在线调整规则（开关/等级/阈值）并持久化，返回更新后的规则。"""
        target = next((r for r in self.rules if r.id == rule_id), None)
        if target is None:
            return None
        override = self.overrides.setdefault(rule_id, {})
        if enabled is not None:
            target.enabled = enabled
            override["enabled"] = enabled
        if severity is not None:
            target.severity = severity
            override["severity"] = severity
        if threshold is not None:
            target.threshold = threshold
            override["threshold"] = threshold.model_dump()
        self._save_overrides()
        return target

    def reload_if_changed(self) -> bool:
        """检查规则目录是否有变化，有则重新加载（供后台定时任务调用）。"""
        check = [Path(self.rules_dir).glob("*.y*ml")]
        current: dict[str, float] = {}
        for pattern in check:
            for path in pattern:
                if path.name.startswith("_"):
                    continue
                current[path.name] = path.stat().st_mtime
        if current != self._signature:
            self._signature = current
            self.load()
            return True
        return False

    # ---------------- 后台自定义规则 ----------------

    def _managed_path(self) -> Path:
        """返回后台自定义规则文件路径。"""
        return self.rules_dir / MANAGED_FILE

    def _read_managed_dicts(self) -> list[dict[str, Any]]:
        """读取自定义规则文件中的原始规则字典列表。"""
        path = self._managed_path()
        if not path.exists():
            return []
        return self._read_rule_file(path)

    def _read_managed_ids(self) -> list[str]:
        """读取自定义规则文件中全部规则 ID。"""
        return [str(item.get("id")) for item in self._read_managed_dicts() if item.get("id")]

    def is_managed(self, rule_id: str) -> bool:
        """判断规则是否为后台新增/管理的自定义规则。"""
        return rule_id in self.managed_ids

    def _write_managed(self, rules_data: list[dict[str, Any]]) -> None:
        """把自定义规则列表写回 YAML 文件。"""
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        content = yaml.safe_dump(
            {"rules": rules_data}, allow_unicode=True, sort_keys=False, default_flow_style=False
        )
        self._managed_path().write_text(content, encoding="utf-8")

    def _drop_override(self, rule_id: str) -> None:
        """删除某条规则的运行期覆盖配置（自定义规则以文件内容为准）。"""
        if rule_id in self.overrides:
            self.overrides.pop(rule_id)
            self._save_overrides()

    def upsert_managed(self, rule: Rule) -> Rule:
        """新增或更新一条自定义规则并立即重新加载，返回生效后的规则对象。"""
        rules_data = self._read_managed_dicts()
        # enabled_source 为运行期字段，不应写入 YAML
        payload = rule.model_dump(by_alias=True, exclude={"enabled_source"})
        replaced = False
        for index, item in enumerate(rules_data):
            if item.get("id") == rule.id:
                rules_data[index] = payload
                replaced = True
                break
        if not replaced:
            rules_data.append(payload)
        self._write_managed(rules_data)
        self._drop_override(rule.id)
        self.load()
        target = next((r for r in self.rules if r.id == rule.id), None)
        if target is None:  # 理论上不会发生，刚写入就应能加载到
            raise ValueError(f"规则 {rule.id} 写入后加载失败")
        return target

    def delete_managed(self, rule_id: str) -> bool:
        """删除一条自定义规则，返回是否实际删除。"""
        rules_data = self._read_managed_dicts()
        remaining = [item for item in rules_data if item.get("id") != rule_id]
        if len(remaining) == len(rules_data):
            return False
        self._write_managed(remaining)
        self._drop_override(rule_id)
        self.load()
        return True

    def upsert_managed_batch(self, rules: list[Rule]) -> None:
        """按 ID 批量新增/更新自定义规则，仅写盘并重载一次。"""
        rules_data = self._read_managed_dicts()
        index_by_id = {item.get("id"): index for index, item in enumerate(rules_data)}
        for rule in rules:
            payload = rule.model_dump(by_alias=True, exclude={"enabled_source"})
            if rule.id in index_by_id:
                rules_data[index_by_id[rule.id]] = payload
            else:
                index_by_id[rule.id] = len(rules_data)
                rules_data.append(payload)
        # 覆盖更新后以文件内容为准，统一清理这些规则的运行期覆盖配置
        for rule in rules:
            self._drop_override(rule.id)
        self._write_managed(rules_data)
        self.load()


def normalize_rule_dict(raw: dict[str, Any]) -> dict[str, Any]:
    """把 YAML 中 `in` 等 Python 关键字字段转换为模型字段名。"""
    data = dict(raw)

    def convert_conditions(conditions: Any) -> list[dict[str, Any]]:
        """递归转换条件列表中的 in 字段。"""
        result: list[dict[str, Any]] = []
        for cond in conditions or []:
            if not isinstance(cond, dict):
                continue
            item = dict(cond)
            if "in" in item:
                item["in_"] = item.pop("in")
            result.append(item)
        return result

    if "all_of" in data:
        data["all_of"] = convert_conditions(data["all_of"])
    if "any_of" in data:
        data["any_of"] = convert_conditions(data["any_of"])
    return data


def rule_to_dict(rule: Rule) -> dict[str, Any]:
    """把规则对象转成可序列化的字典（供 API 返回）。"""
    return rule.model_dump(by_alias=True)


__all__ = ["RuleLoader", "rule_to_dict", "RuleCondition"]
