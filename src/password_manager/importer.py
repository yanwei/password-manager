"""导入器 —— 1PUX（ZIP + JSON）与扁平 CSV。

1PUX 才是信息完整的那份：它保留了分类、自定义字段、附件、密码历史、归档状态。
实测同一账号导出的 CSV 只有 228 行、且全部塌缩成 Login（丢了 Document /
Bank Account / Server / Wireless Router 等分类，也丢了自定义字段）。所以
CSV 只作为兜底通道，1PUX 是首选。

幂等键用 1Password 自己的 `item.uuid`，重复导入同一份文件只会更新不会翻倍。
"""

from __future__ import annotations

import base64
import csv
import io
import json
import zipfile
from pathlib import Path

from .crypto import VaultError
from .models import (
    Field,
    Item,
    SECRET_KINDS,
    category_of,
    decode_value,
    new_id,
    now_ts,
)

#: 附件内联进保险库的大小上限。超过则只保留元信息（文件名/大小），不搬运字节。
MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024


def load_any(
    source: str | Path, *, include_archived: bool = True
) -> tuple[list[Item], dict]:
    """按文件类型自动分派。返回 (条目列表, 元信息)。"""
    path = Path(source)
    if not path.exists():
        raise VaultError(f"文件不存在：{path}")
    suffix = path.suffix.lower()
    if suffix in (".1pux", ".pux") or zipfile.is_zipfile(path):
        return load_1pux(path, include_archived=include_archived)
    if suffix in (".csv", ".tsv"):
        return load_csv(path, include_archived=include_archived)
    if suffix == ".json":
        return load_json_export(path, include_archived=include_archived)
    raise VaultError(f"不认识的文件类型：{suffix or path.name}（支持 .1pux / .csv / .json）")


# ── 1PUX ─────────────────────────────────────────────────────────────────────


def load_1pux(
    source: str | Path, *, include_archived: bool = True
) -> tuple[list[Item], dict]:
    """解析 1Password Unencrypted Export (.1pux)。"""
    path = Path(source)
    if not zipfile.is_zipfile(path):
        raise VaultError(f"{path.name} 不是合法的 1PUX（不是 ZIP 压缩包）。")

    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if "export.data" not in names:
            raise VaultError("1PUX 里缺少 export.data，文件可能已损坏。")
        try:
            data = json.loads(archive.read("export.data").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultError(f"export.data 解析失败：{exc}") from exc

        attributes = {}
        if "export.attributes" in names:
            try:
                attributes = json.loads(archive.read("export.attributes").decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                attributes = {}

        blobs = {
            name.split("/", 1)[1]: archive.read(name)
            for name in names
            if name.startswith("files/") and not name.endswith("/")
        }

    accounts = data.get("accounts") or []
    if not accounts:
        raise VaultError("1PUX 里没有账号数据。")

    items: list[Item] = []
    account_names: list[str] = []
    for account in accounts:
        attrs = account.get("attrs") or {}
        account_names.append(attrs.get("name") or attrs.get("accountName") or "未命名账号")
        for vault in account.get("vaults") or []:
            vault_name = (vault.get("attrs") or {}).get("name", "")
            for raw in vault.get("items") or []:
                if raw.get("state") == "archived" and not include_archived:
                    continue
                items.append(_item_from_1pux(raw, vault_name, blobs))

    meta = {
        "source": "1pux",
        "source_account": "、".join(account_names),
        "source_file": path.name,
        "export_format_version": attributes.get("version"),
        "export_created_at": attributes.get("timestamp") or attributes.get("createdAt"),
        "last_import_at": now_ts(),
    }
    return items, meta


def _item_from_1pux(raw: dict, vault_name: str, blobs: dict[str, bytes]) -> Item:
    """把一条 1PUX item 转成内部 Item。"""
    details = raw.get("details") or {}
    overview = raw.get("overview") or {}
    spec = category_of(str(raw.get("categoryUuid") or "001"))

    item = Item(
        id=new_id(str(raw.get("uuid") or "")),
        title=(overview.get("title") or "").strip() or "未命名条目",
        category=spec.slug,
        category_uuid=spec.uuid,
        vault=vault_name,
        tags=list(overview.get("tags") or []),
        notes=(details.get("notesPlain") or "").strip(),
        favorite=int(raw.get("favIndex") or 0) > 0,
        archived=raw.get("state") == "archived",
        created_at=int(raw.get("createdAt") or 0),
        updated_at=int(raw.get("updatedAt") or 0),
        source="1pux",
        source_id=str(raw.get("uuid") or ""),
    )

    # ── URL ──
    urls: list[dict] = []
    for entry in overview.get("urls") or []:
        url = (entry or {}).get("url")
        if url:
            urls.append({"label": entry.get("label") or "website", "url": url})
    primary = overview.get("url")
    if primary and not any(u["url"] == primary for u in urls):
        urls.insert(0, {"label": "website", "url": primary})
    for index, entry in enumerate(urls):
        entry["primary"] = index == 0
    item.urls = urls

    # ── 内置字段：非 Login 分类没有 username/password 顶层字段，需要从 sections 里认 ──
    is_login = spec.slug == "login"
    for section in details.get("sections") or []:
        section_title = (section.get("title") or "").strip()
        if section_title in ("Related Items", "linked items"):
            continue  # 关联项在 1PUX 里只有 uuid 引用，落库成字段没有可读价值
        for entry in section.get("fields") or []:
            if not isinstance(entry, dict):
                continue
            text, kind = decode_value(entry.get("value"))
            if text in ("", None):
                continue
            field = Field(
                title=(entry.get("title") or "").strip(),
                value=text,
                kind=kind,
                section=section_title,
                field_id=str(entry.get("id") or ""),
                secret=bool(entry.get("guarded")) or kind in SECRET_KINDS,
                multiline=bool(entry.get("multiline")),
            )
            if not field.title:
                field.title = field.field_id or "未命名字段"
            # 只有 Login 才把 username/password 提升到顶层——这是 1Password 自己的
            # 模型边界。服务器/数据库/路由器这类条目的凭据必须留在带标签的字段里，
            # 提升会抹掉「运营商密码」这类用户自定义标签。
            if is_login and field.field_id in ("username", "password"):
                _assign_builtin(item, field)
            else:
                item.fields.append(field)

    # Password 分类的密码单独躺在 details.password 里
    if not item.password and details.get("password"):
        item.password = str(details["password"])

    # ── 登录表单字段 ──
    # designation=username/password 提升成内置字段；其余归入"网页表单详情"。
    for entry in details.get("loginFields") or []:
        if not isinstance(entry, dict):
            continue
        value = entry.get("value")
        text = value if isinstance(value, str) else decode_value(value)[0]
        designation = (entry.get("designation") or "").strip().lower()
        if designation == "username":
            item.username = item.username or text
            continue
        if designation == "password":
            item.password = item.password or text
            continue
        if text in ("", None):
            continue
        field_type = str(entry.get("fieldType") or "")
        item.form_fields.append(
            Field(
                title=(entry.get("name") or entry.get("id") or "字段").strip(),
                value=text,
                kind="concealed" if field_type == "P" else "string",
                section="网页表单",
                field_id=str(entry.get("id") or ""),
                secret=field_type == "P",
            )
        )

    # ── 密码历史 ──
    item.password_history = [
        {"value": str(h.get("value", "")), "time": int(h.get("time") or 0)}
        for h in (details.get("passwordHistory") or [])
        if isinstance(h, dict) and h.get("value")
    ][:20]

    # ── 附件 ──
    item.attachments = _collect_attachments(details.get("documentAttributes"), blobs)

    return item


def _assign_builtin(item: Item, field: Field) -> None:
    """把明显是内置语义的字段提升到顶层，其余留在 fields 里。"""
    if field.field_id == "username" and not item.username:
        item.username = field.value
        return
    if field.field_id == "password" and not item.password:
        item.password = field.value
        return
    item.fields.append(field)


def _collect_attachments(attributes: dict | None, blobs: dict[str, bytes]) -> list[dict]:
    """收集附件：小文件内联 base64，大文件只留元信息。"""
    if not attributes:
        return []
    document_id = str(attributes.get("documentId") or "")
    file_name = str(attributes.get("fileName") or "attachment")
    size = int(attributes.get("decryptedSize") or 0)
    entry = {
        "name": file_name,
        "size": size,
        "mime": _guess_mime(file_name),
        "inline": False,
        "data": "",
    }

    blob = blobs.get(f"{document_id}__{file_name}")
    if blob is None:
        # 文件名里的 1Password 后缀不一定存在，退化成前缀匹配
        for key, value in blobs.items():
            if key.startswith(f"{document_id}__"):
                blob = value
                break
    if blob is not None:
        entry["size"] = len(blob)
        if len(blob) <= MAX_ATTACHMENT_BYTES:
            entry["inline"] = True
            entry["data"] = base64.b64encode(blob).decode("ascii")
        else:
            entry["too_large"] = True
    elif document_id:
        entry["missing"] = True
    return [entry]


def _guess_mime(filename: str) -> str:
    import mimetypes

    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


# ── CSV ──────────────────────────────────────────────────────────────────────

#: 1Password CSV 导出的列名 → 内部语义
_CSV_COLUMNS = {
    "title": "title",
    "name": "title",
    "url": "url",
    "website": "url",
    "username": "username",
    "login": "username",
    "password": "password",
    "otpauth": "otp",
    "notes": "notes",
    "tags": "tags",
    "favorite": "favorite",
    "archived": "archived",
}


def load_csv(
    source: str | Path, *, include_archived: bool = True
) -> tuple[list[Item], dict]:
    """解析扁平 CSV（1Password / Bitwarden / Chrome 的通用列名都认）。"""
    path = Path(source)
    text = _read_text(path)
    try:
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
    except csv.Error as exc:
        raise VaultError(f"CSV 解析失败：{exc}") from exc
    if not rows:
        raise VaultError("CSV 里没有数据行。")

    mapping = {}
    for column in rows[0].keys():
        key = _CSV_COLUMNS.get((column or "").strip().lower())
        if key:
            mapping[column] = key
    if "title" not in mapping.values():
        raise VaultError(f"CSV 缺少标题列，实际列：{list(rows[0].keys())}")

    items: list[Item] = []
    for row in rows:
        values = {
            mapping[col]: (row.get(col) or "").strip()
            for col in mapping
            if row.get(col) is not None
        }
        if not values.get("title"):
            continue
        archived = values.get("archived", "").upper() in ("TRUE", "1", "YES", "Y")
        if archived and not include_archived:
            continue
        tags_raw = values.get("tags", "")
        tags = [t.strip() for t in _split_tags(tags_raw) if t.strip()]
        item = Item(
            id=new_id(),
            title=values["title"],
            category="login",
            category_uuid="001",
            username=values.get("username", ""),
            password=values.get("password", ""),
            otp=values.get("otp", ""),
            urls=[{"label": "website", "url": values["url"], "primary": True}]
            if values.get("url")
            else [],
            tags=tags,
            notes=values.get("notes", ""),
            favorite=values.get("favorite", "").upper() in ("TRUE", "1", "YES", "Y"),
            archived=archived,
            source="csv",
            source_id="",
        )
        items.append(item)

    meta = {
        "source": "csv",
        "source_file": path.name,
        "last_import_at": now_ts(),
    }
    return items, meta


def _split_tags(raw: str) -> list[str]:
    """标签列可能用逗号、分号或换行分隔，全部兼容。"""
    if not raw:
        return []
    for sep in (";", "|", "\n"):
        if sep in raw:
            return raw.split(sep)
    return raw.split(",")


# ── JSON（pm 自己的导出格式） ────────────────────────────────────────────────


def load_json_export(
    source: str | Path, *, include_archived: bool = True
) -> tuple[list[Item], dict]:
    """回读 `pm export` 产出的 JSON，用于跨机迁移。"""
    path = Path(source)
    try:
        payload = json.loads(_read_text(path))
    except json.JSONDecodeError as exc:
        raise VaultError(f"JSON 解析失败：{exc}") from exc
    rows = payload.get("items") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise VaultError("JSON 结构不认识：期望顶层是条目数组，或含 items 数组的对象。")
    items = [Item.from_dict(row) for row in rows if isinstance(row, dict)]
    if not include_archived:
        items = [i for i in items if not i.archived]
    meta = {
        "source": "json",
        "source_file": path.name,
        "last_import_at": now_ts(),
    }
    return items, meta


def _read_text(path: Path) -> str:
    for encoding in ("utf-8-sig", "utf-8", "gb18030", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    raise VaultError(f"无法解码文件编码：{path}")
