"""密码强度评估与安全审计。

强度估算不引入 zxcvbn 这类重依赖，用「字符集熵 − 结构化惩罚」实现：先算理论
熵，再对连续字符、重复字符、键盘序列、常见弱口令、日期/年份内嵌等模式扣分。
目标是给出可排序的相对强弱与可执行的改进建议，而不是宣称精确的破解时间。
"""

from __future__ import annotations

import math
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field as dc_field

# ── 强度评估 ─────────────────────────────────────────────────────────────────

#: 高频弱口令（小写比对）。不求全，覆盖最常见的几类足够触发警告。
COMMON_PASSWORDS = frozenset(
    """
    123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon
    123123 baseball abc123 football monkey letmein 696969 shadow master 666666
    qwertyuiop 123321 mustang 1234567890 michael 654321 pussy superman 1qaz2wsx
    7777777 fuckme 121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer
    zxcvbnm asdfgh hunter buster soccer harley batman andrew tigger sunshine
    iloveyou fuckyou 2000 charlie robert thomas hockey ranger daniel starwars
    klaster 112233 george asshole computer michelle jessica pepper 1111 zxcvbn
    tigger1 555555 11111111 131313 freedom 777777 pass fuckmylife maggie 159753
    aaaaaa ginger princess joshua cheese amanda summer love ashley nicole
    chelsea biteme matthew access yankees 987654321 dallas austin thunder taylor
    matrix mobilemail mom monitor montana moon moscow pass passwd admin root
    administrator guest test test123 demo changeme secret default
    """.split()
)

_SEQ_ROWS = (
    "abcdefghijklmnopqrstuvwxyz",
    "01234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

LEVELS = ("极弱", "弱", "一般", "强", "极强")


@dataclass
class Strength:
    """一次强度评估的结果。"""

    score: int  # 0-4，越大越强
    bits: float  # 估算信息熵（bit）
    label: str
    warnings: list[str] = dc_field(default_factory=list)

    @property
    def percent(self) -> int:
        """映射成 0-100 的展示百分比。"""
        return max(4, min(100, int(self.bits / 100 * 100)))


def charset_size(password: str) -> int:
    """估算字符集大小。"""
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        size += 33
    return max(size, 1)


def _longest_run(password: str, kind: str) -> int:
    """最长连续序列长度：kind = 'repeat' 单字符重复 / 'seq' 键盘或字母表递增。"""
    best = 1
    run = 1
    for i in range(1, len(password)):
        cur, prev = password[i], password[i - 1]
        if kind == "repeat":
            if cur == prev:
                run += 1
            else:
                run = 1
        else:
            if ord(cur) - ord(prev) in (1, -1) or _same_row_adjacent(prev, cur):
                run += 1
            else:
                run = 1
        best = max(best, run)
    return best


def _same_row_adjacent(a: str, b: str) -> bool:
    for row in _SEQ_ROWS:
        if a in row and b in row and abs(row.index(a) - row.index(b)) == 1:
            return True
    return False


def evaluate(password: str) -> Strength:
    """评估密码强度。空密码直接判 0 分。"""
    if not password:
        return Strength(0, 0.0, LEVELS[0], ["密码为空"])

    bits = len(password) * math.log2(charset_size(password))
    warnings: list[str] = []
    lowered = password.lower()

    repeat = _longest_run(password, "repeat")
    if repeat >= 3:
        bits *= max(0.35, 1 - 0.15 * (repeat - 2))
        warnings.append(f"有 {repeat} 个连续相同字符")
    seq = _longest_run(password, "seq")
    if seq >= 4:
        bits *= max(0.4, 1 - 0.12 * (seq - 3))
        warnings.append(f"有 {seq} 位连续键盘/字母序列")

    normalized = lowered.translate(_LEET)
    if lowered in COMMON_PASSWORDS or normalized in COMMON_PASSWORDS:
        bits = min(bits, 16.0)
        warnings.append("属于常见弱口令")
    elif any(w in normalized for w in COMMON_PASSWORDS if len(w) >= 5):
        bits *= 0.6
        warnings.append("包含常见弱口令片段")

    if re.fullmatch(r"\d+", password):
        bits *= 0.75
        warnings.append("纯数字")
    if re.search(r"(19|20)\d{2}", password):
        bits *= 0.85
        warnings.append("含年份")
    if re.search(r"\d{4}[-/.]?\d{2}[-/.]?\d{2}", password):
        bits *= 0.85
        warnings.append("含日期样式")

    for pattern, label in (
        (r"^[a-z]+$", "只有小写字母"),
        (r"^[A-Za-z]+$", "只有字母"),
        (r"^[A-Za-z0-9]+$", "缺少符号"),
    ):
        if re.fullmatch(pattern, password):
            warnings.append(label)

    if len(password) < 8:
        warnings.append("长度不足 8 位")

    if bits < 28:
        score = 0
    elif bits < 45:
        score = 1
    elif bits < 66:
        score = 2
    elif bits < 90:
        score = 3
    else:
        score = 4
    # 结构性缺陷不该被长度刷过：命中常见口令一律压到 1 分以内
    if "属于常见弱口令" in warnings:
        score = min(score, 1)
    if len(password) < 8:
        score = min(score, 1)

    # 只有确实偏弱时才把细节抛给用户。20 位随机密码里凑巧出现 "2018" 并不值得
    # 提醒——那只是让人对警告脱敏的噪音。
    visible = warnings if score <= 2 else []

    return Strength(score, round(bits, 1), LEVELS[score], visible)


# ── 安全审计 ─────────────────────────────────────────────────────────────────

#: 默认认为「过旧」的阈值（天）
STALE_DAYS = 730
#: 密码历史的保留上限
HISTORY_LIMIT = 20

ISSUE_LABELS = {
    "weak": "弱密码",
    "reused": "重复使用",
    "stale": "长期未更新",
    "empty": "无密码",
}


@dataclass
class Finding:
    """一条审计发现。"""

    kind: str
    item_id: str
    title: str
    detail: str
    score: int = 0

    @property
    def label(self) -> str:
        return ISSUE_LABELS.get(self.kind, self.kind)


@dataclass
class AuditReport:
    """整体审计报告。"""

    total: int = 0
    archived: int = 0
    with_password: int = 0
    #: 携带历史密码的条目数。这是 1Password 的正常特性，只作提示、不计入问题
    with_history: int = 0
    findings: list[Finding] = dc_field(default_factory=list)
    score_histogram: list[int] = dc_field(default_factory=lambda: [0, 0, 0, 0, 0])
    tag_counts: dict[str, int] = dc_field(default_factory=dict)
    category_counts: dict[str, int] = dc_field(default_factory=dict)
    oldest_updated: int = 0
    newest_updated: int = 0

    @property
    def by_kind(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for f in self.findings:
            grouped[f.kind].append(f)
        return dict(grouped)

    @property
    def health(self) -> int:
        """0-100 的健康分：从 100 分起按问题密度扣。"""
        if not self.with_password:
            return 100
        weights = {"weak": 4, "reused": 3, "empty": 2, "stale": 1}
        penalty = sum(weights.get(f.kind, 1) for f in self.findings)
        return max(0, 100 - int(penalty * 100 / (self.with_password * 4)))


def audit(items: list, *, stale_days: int = STALE_DAYS) -> AuditReport:
    """对条目集合做安全体检，返回汇总 + 明细。"""
    report = AuditReport()
    report.total = len(items)
    report.archived = sum(1 for i in items if i.archived)

    # 重复使用检测：按密文分组，同一密码出现在多个条目即为复用
    seen: dict[str, list] = defaultdict(list)
    cutoff = time.time() - stale_days * 86400

    for item in items:
        report.category_counts[item.category_name] = (
            report.category_counts.get(item.category_name, 0) + 1
        )
        for tag in item.tags:
            report.tag_counts[tag] = report.tag_counts.get(tag, 0) + 1
        if item.updated_at:
            report.oldest_updated = min(
                report.oldest_updated or item.updated_at, item.updated_at
            )
            report.newest_updated = max(report.newest_updated, item.updated_at)

        if item.archived:
            continue

        # 用 secret_value 而不是 item.password：服务器/路由器/数据库这类条目的
        # 密码在带标签的自定义字段里，漏掉它们等于没审计。
        secret = item.secret_value
        if not secret:
            if item.category == "login":
                report.findings.append(
                    Finding("empty", item.id, item.title, "登录条目没有记录密码")
                )
            continue

        report.with_password += 1
        strength = evaluate(secret)
        report.score_histogram[strength.score] += 1

        if strength.score <= 1:
            detail = "、".join(strength.warnings[:3]) or "强度不足"
            report.findings.append(
                Finding("weak", item.id, item.title, f"{strength.label} · {detail}", strength.score)
            )

        seen[secret].append(item)

        if item.updated_at and item.updated_at < cutoff:
            days = int((time.time() - item.updated_at) / 86400)
            report.findings.append(
                Finding("stale", item.id, item.title, f"已 {days} 天未更新")
            )

        if item.password_history:
            report.with_history += 1

    for password, users in seen.items():
        if len(users) < 2:
            continue
        names = "、".join(u.title for u in users[:4])
        names += f" 等 {len(users)} 条" if len(users) > 4 else ""
        for item in users:
            report.findings.append(
                Finding("reused", item.id, item.title, f"同一密码还用于：{names}")
            )

    report.findings.sort(key=lambda f: (f.label, f.title.lower()))
    return report
