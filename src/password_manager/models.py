"""数据模型 —— Item / Field、1Password 分类映射、字段值变体解码。

字段值变体（1PUX 实际出现的 9 种）
----------------------------------
`{"string": ...}` `{"concealed": ...}` `{"menu": ...}` `{"url": ...}`
`{"email": {...}}` `{"date": int}` `{"phone": ...}` `{"reference": ...}`
`{"ssoLogin": {...}}`，空字段则直接是 `{}`。

刻意不做的事
------------
**不按字段 id 反查英文标签。** 导出文件里用户已经把标题改成中文（例如
Wireless Router 里的 `xywlqgbafhwzafpjpmxfzoyybq` → 「管理密码」），任何
"id → 官方英文名" 的映射都会覆盖掉用户自己的命名。字段标题一律原样保留。
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import asdict, dataclass, field as dc_field
from datetime import UTC, datetime, timedelta

# ── 1Password 分类映射 ───────────────────────────────────────────────────────
#
# verified=True 的条目已在本次真实导出数据中逐一核对过字段模板；
# 其余按 1Password 公开的分类编号约定登记，遇到未登记的 UUID 会显式回落成
# 「未知分类 (code)」而不是猜一个名字。


@dataclass(frozen=True)
class Category:
    uuid: str
    slug: str
    name_zh: str
    name_en: str
    verified: bool = False


CATEGORIES: dict[str, Category] = {
    c.uuid: c
    for c in [
        Category("001", "login", "登录", "Login", True),
        Category("002", "credit_card", "信用卡", "Credit Card"),
        Category("003", "secure_note", "安全笔记", "Secure Note", True),
        Category("004", "identity", "身份", "Identity"),
        Category("005", "password", "密码", "Password", True),
        Category("006", "document", "文档", "Document", True),
        Category("100", "software_license", "软件许可", "Software License", True),
        Category("101", "bank_account", "银行账户", "Bank Account", True),
        Category("102", "database", "数据库", "Database", True),
        Category("103", "driver_license", "驾照", "Driver License"),
        Category("104", "outdoor_license", "户外许可", "Outdoor License"),
        Category("105", "membership", "会员", "Membership"),
        Category("106", "passport", "护照", "Passport"),
        Category("107", "rewards", "积分计划", "Rewards Program"),
        Category("108", "social_security", "社保号", "Social Security Number"),
        Category("109", "wireless_router", "无线路由器", "Wireless Router", True),
        Category("110", "server", "服务器", "Server", True),
        Category("111", "api_credential", "API 凭据", "API Credential"),
        Category("112", "email_account", "邮箱账户", "Email Account"),
        Category("113", "medical_record", "医疗记录", "Medical Record"),
        Category("114", "ssh_key", "SSH 密钥", "SSH Key"),
        Category("115", "crypto_wallet", "加密钱包", "Crypto Wallet"),
    ]
}

#: 现场新增条目时的默认分类
DEFAULT_CATEGORY = "login"

#: slug → uuid，用于手工新增条目
_SLUG_TO_UUID = {c.slug: c.uuid for c in CATEGORIES.values()}


def category_of(uuid_str: str) -> Category:
    """按 UUID 取分类；未登记则回落到「未知分类」。"""
    got = CATEGORIES.get(uuid_str)
    if got is not None:
        return got
    return Category(uuid_str, f"unknown_{uuid_str}", f"未知分类 ({uuid_str})", "Unknown")


def category_by_slug(slug: str) -> Category:
    """按 slug 取分类，找不到就当登录处理。"""
    uuid_str = _SLUG_TO_UUID.get(slug)
    return CATEGORIES.get(uuid_str or "", CATEGORIES["001"])


def all_categories() -> list[Category]:
    """已登记分类，按 UUID 排序。"""
    return [CATEGORIES[k] for k in sorted(CATEGORIES)]


# ── 时间 ─────────────────────────────────────────────────────────────────────

#: 1Password 旧格式使用 Core Foundation 纪元（2001-01-01）表示日期字段
_CF_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)
#: 判定"这是 CF 纪元而非 Unix 纪元"的合理区间
_SANE_MIN = datetime(2000, 1, 1, tzinfo=UTC)


def decode_date(raw: int) -> tuple[str, int]:
    """把 1PUX 的 date 字段解成 (ISO 字符串, unix 时间戳)。

    坑：同一份导出里 date 字段的纪元并不统一。实测 `1381449539` 按 Unix 是
    2013 年（合理），而 `485265660` 按 Unix 是 1985 年（荒谬）、按 Core
    Foundation 纪元才是 2016 年（合理）。所以先按官方说明当 Unix 解，若落在
    2000 年之前而 CF 纪元解释落在 2001 年之后，则采用 CF 纪元。
    """
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return "", 0

    unix_dt = datetime.fromtimestamp(value, tz=UTC)
    if unix_dt < _SANE_MIN:
        cf_dt = _CF_EPOCH + timedelta(seconds=value)
        if cf_dt >= _SANE_MIN:
            unix_dt = cf_dt
            value = int(cf_dt.timestamp())
    if unix_dt.year < 1970 or unix_dt.year > 2200:
        return "", 0
    return unix_dt.strftime("%Y-%m-%d %H:%M"), value


def ts_to_iso(ts: int | None) -> str:
    """Unix 时间戳 → 本地可读时间。"""
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError, OverflowError):
        return ""


def ts_to_date(ts: int | None) -> str:
    """Unix 时间戳 → 日期（仅到天）。"""
    iso = ts_to_iso(ts)
    return iso.split(" ")[0] if iso else ""


def humanize(ts: int | None) -> str:
    """时间戳 → 「3 天前」这类相对描述。"""
    if not ts:
        return "—"
    delta = time.time() - int(ts)
    if delta < 0:
        return ts_to_date(ts)
    for limit, unit, div in (
        (60, "秒", 1),
        (3600, "分钟", 60),
        (86400, "小时", 3600),
        (86400 * 30, "天", 86400),
        (86400 * 365, "个月", 86400 * 30),
    ):
        if delta < limit:
            return f"{int(delta / div)}{unit}前"
    return f"{int(delta / (86400 * 365))}年前"


def now_ts() -> int:
    return int(time.time())


# ── 字段值解码 ───────────────────────────────────────────────────────────────

#: 1PUX 字段值变体 → 内部 kind
_VALUE_KINDS = (
    "string",
    "concealed",
    "menu",
    "url",
    "email",
    "date",
    "phone",
    "reference",
    "ssoLogin",
    "address",
    "monthYear",
    "totp",
    "file",
)

#: 默认按密文处理的 kind
SECRET_KINDS = frozenset({"concealed", "totp"})


def decode_value(value) -> tuple[str, str]:
    """把一个 1PUX 字段值解成 (可读文本, kind)。

    未知变体不会丢数据——递归 flatten 成文本返回，kind 记为 unknown。
    """
    if value is None:
        return "", "empty"
    if isinstance(value, str):
        return value, "string"
    if not isinstance(value, dict) or not value:
        return "", "empty"

    for kind in _VALUE_KINDS:
        if kind not in value:
            continue
        raw = value[kind]
        if kind == "date":
            text, _ = decode_date(raw)
            return text, "date"
        if kind == "email":
            if isinstance(raw, dict):
                return str(raw.get("email_address") or ""), "email"
            return str(raw or ""), "email"
        if kind == "phone":
            return str(raw or ""), "phone"
        if kind == "address":
            if isinstance(raw, dict):
                parts = [raw.get(k) for k in ("street", "city", "state", "zip", "country")]
                return " ".join(str(p) for p in parts if p), "address"
            return str(raw or ""), "address"
        if kind == "ssoLogin":
            if isinstance(raw, dict):
                return f"SSO · {raw.get('provider') or '第三方'}", "ssoLogin"
            return "SSO", "ssoLogin"
        if kind == "file":
            if isinstance(raw, dict):
                return str(raw.get("fileName") or raw.get("name") or ""), "file"
            return "", "file"
        if kind == "monthYear":
            text = str(raw)
            if len(text) == 6 and text.isdigit():
                return f"{text[:4]}-{text[4:]}", "monthYear"
            return text, "monthYear"
        return str(raw if raw is not None else ""), kind

    # 未登记变体：flatten 保底，绝不静默丢字段
    parts: list[str] = []

    def _walk(node) -> None:
        if isinstance(node, dict):
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)
        elif node not in (None, ""):
            parts.append(str(node))

    _walk(value)
    return " ".join(parts), "unknown"


# ── 模型 ─────────────────────────────────────────────────────────────────────


@dataclass
class Field:
    """条目上的一个自定义字段（来自 1PUX 的 sections[].fields[]）。"""

    title: str
    value: str = ""
    kind: str = "string"
    section: str = ""
    field_id: str = ""
    secret: bool = False
    multiline: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(raw: dict) -> Field:
        known = {f for f in Field.__dataclass_fields__}
        return Field(**{k: v for k, v in raw.items() if k in known})


@dataclass
class Item:
    """一条密码条目。字段命名直接对齐 JSON 持久化格式，不做二次映射。"""

    id: str
    title: str
    category: str = DEFAULT_CATEGORY
    category_uuid: str = "001"
    vault: str = ""
    username: str = ""
    password: str = ""
    otp: str = ""
    urls: list[dict] = dc_field(default_factory=list)
    tags: list[str] = dc_field(default_factory=list)
    notes: str = ""
    fields: list[Field] = dc_field(default_factory=list)
    form_fields: list[Field] = dc_field(default_factory=list)
    password_history: list[dict] = dc_field(default_factory=list)
    attachments: list[dict] = dc_field(default_factory=list)
    favorite: bool = False
    archived: bool = False
    created_at: int = 0
    updated_at: int = 0
    source: str = "manual"
    source_id: str = ""

    # ── 派生属性 ────────────────────────────────────────────────────────────

    @property
    def category_name(self) -> str:
        return category_of(self.category_uuid).name_zh

    @property
    def primary_url(self) -> str:
        """主 URL：优先 overview.url，其次 urls[] 的第一条。"""
        for entry in self.urls:
            if entry.get("primary") and entry.get("url"):
                return entry["url"]
        for entry in self.urls:
            if entry.get("url"):
                return entry["url"]
        return ""

    @property
    def host(self) -> str:
        """主 URL 的主机名，列表里用来替代过长 URL。"""
        url = self.primary_url
        if not url:
            return ""
        stripped = url.split("://", 1)[-1]
        return stripped.split("/", 1)[0].split("?", 1)[0]

    @property
    def secret_value(self) -> str:
        """用于复制/审计的那个密文。

        非 Login 分类（服务器、数据库、无线路由器…）没有顶层 password 字段，
        密码躺在带标签的自定义字段里（例如「运营商密码」「license key」）。
        硬把这类字段提升成顶层 `password` 会丢掉用户自己的标签，所以这里反过来
        做：保留字段原样，取密文时按「顶层 password → 第一个非空密文字段」回落。
        """
        if self.password:
            return self.password
        for field in self.fields:
            if field.secret and field.value:
                return field.value
        return ""

    @property
    def secret_label(self) -> str:
        """密文对应的展示标签，用于提示复制的到底是哪一个字段。"""
        if self.password:
            return "密码"
        for field in self.fields:
            if field.secret and field.value:
                return f"{field.section} · {field.title}" if field.section else field.title
        return ""

    @property
    def has_secret(self) -> bool:
        return bool(self.secret_value)

    @property
    def secret_field_count(self) -> int:
        """密码之外的密文字段数量，列表里用锁图标提示。"""
        return sum(1 for f in self.fields if f.secret and f.value)

    def display_fields(self) -> list[tuple[str, str, bool]]:
        """统一的展示列表：[(标签, 值, 是否密文)]，含内置字段与自定义字段。

        刻意**不含**网页表单详情（form_fields）——那部分是浏览器扩展抓取的
        表单原始数据，量级大且噪音多，只在明细视图里按需展开。
        """
        rows: list[tuple[str, str, bool]] = []
        if self.username:
            rows.append(("用户名", self.username, False))
        if self.password:
            rows.append(("密码", self.password, True))
        if self.otp:
            rows.append(("一次性密码", self.otp, True))
        for entry in self.urls:
            if entry.get("url"):
                rows.append((entry.get("label") or "网址", entry["url"], False))
        for f in self.fields:
            if f.value in ("", None):
                continue
            label = f"{f.section} · {f.title}" if f.section else f.title
            rows.append((label, f.value, f.secret))
        for attachment in self.attachments:
            rows.append((f"附件 · {attachment.get('name', '')}", _size_label(attachment), False))
        if self.notes:
            rows.append(("备注", self.notes, False))
        return rows

    def web_form_rows(self) -> list[tuple[str, str, bool]]:
        """网页表单详情（1Password 里默认折叠的那部分）。"""
        return [
            (f.title or f.field_id, f.value, f.secret)
            for f in self.form_fields
            if f.value not in ("", None)
        ]

    def matches(self, query: str) -> bool:
        """模糊匹配：标题 / 用户名 / URL / 标签 / 备注 / 自定义字段标题。"""
        if not query:
            return True
        needle = query.lower()
        haystack = [
            self.title,
            self.username,
            self.notes,
            self.primary_url,
            self.category_name,
            " ".join(self.tags),
            " ".join(f.title for f in self.fields),
            " ".join(f.value for f in self.fields if not f.secret),
        ]
        return any(needle in str(part).lower() for part in haystack)

    def sort_key(self) -> tuple:
        """列表排序：收藏 → 置顶 → 标题。"""
        return (not self.favorite, -(self.updated_at or 0), self.title.lower())

    # ── 序列化 ──────────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        # asdict 会递归处理嵌套的 Field dataclass，无需手工转换
        return asdict(self)

    @staticmethod
    def from_dict(raw: dict) -> Item:
        data = dict(raw)
        data["fields"] = [Field.from_dict(f) for f in data.get("fields") or []]
        data["form_fields"] = [Field.from_dict(f) for f in data.get("form_fields") or []]
        known = {f for f in Item.__dataclass_fields__}
        return Item(**{k: v for k, v in data.items() if k in known})


def _size_label(attachment: dict) -> str:
    """附件大小的人类可读描述。"""
    size = attachment.get("size") or 0
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / 1024 / 1024:.1f} MB"


# ── 构造工具 ─────────────────────────────────────────────────────────────────


def new_id(seed: str = "") -> str:
    """生成条目 id。给 seed 时是确定性哈希，便于导入去重。"""
    if seed:
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
    return uuid.uuid4().hex


def slugify(text: str) -> str:
    """把标题转成适合做命令参数的短标识。"""
    cleaned = [c if (c.isalnum() or c in "-_") else "-" for c in text.strip().lower()]
    slug = "".join(cleaned).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug[:60] or "item"
