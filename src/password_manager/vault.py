"""保险库核心 —— 加密读写、原子落盘、CRUD、搜索。

落盘策略
--------
每次写入都是「读全量 → 改内存 → 整体重新加密 → 原子替换」：

1. 新内容写到同目录的临时文件（权限 0600）；
2. `os.replace()` 原子换名，任何时刻磁盘上要么是完整旧版、要么是完整新版；
3. 换名之前先把旧文件滚动备份成 `<vault>.bak`，抵御程序 bug 导致的逻辑性损坏；
4. 换名之后再把新文件复制一份到备份目录（见 `backup` 模块，默认 iCloud Drive），
   防止"库本身被误删被覆盖"这类落在文件之外的事故。

代价是每次写都是 O(全量)，但 241 条量级的 payload 只有几百 KB，完全无感。
换来的是磁盘上不存在明文、不存在 WAL、不存在半写状态。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import VAULT_FORMAT_VERSION
from .backup import auto_backup
from .crypto import (
    KEYCHAIN_DEFAULT_TTL,
    VaultError,
    VaultNotFound,
    WrongPassword,
    decrypt_payload,
    derive_key,
    encrypt_with_salt,
    keychain_clear,
    keychain_load,
    keychain_store,
    parse_header,
)
from .models import Field, Item, category_by_slug, new_id, now_ts, slugify

__all__ = [
    "Vault",
    "VaultError",
    "WrongPassword",
    "VaultNotFound",
    "ItemNotFound",
    "AmbiguousItem",
    "MergeResult",
    "default_vault_path",
]


class ItemNotFound(VaultError):
    """按关键词找不到条目。"""

    def __init__(self, key: str):
        super().__init__(f"找不到条目：{key}")
        self.key = key


class AmbiguousItem(VaultError):
    """关键词命中多条，需要用户消歧。

    只留一句「命中 N 条 + 怎么指定」：候选明细由调用方（CLI 表格 / Web 提示）
    自己呈现。一条已经带着 8 个 id 的长句子，既读不完，也没法用来区分同名条目。
    """

    def __init__(self, key: str, candidates: list[Item]):
        super().__init__(f"“{key}” 命中 {len(candidates)} 条，用更准确的标题或 id 指定其中一条")
        self.key = key
        self.candidates = candidates


@dataclass
class MergeResult:
    """导入合并结果。"""

    added: int = 0
    updated: int = 0
    skipped: int = 0

    @property
    def total(self) -> int:
        return self.added + self.updated + self.skipped


def default_vault_path() -> Path:
    """默认保险库位置，与**调用方式无关**：`PM_HOME` → 否则永远是 `~/.pm/vault.pmv`。

    曾经有过一条"在源码仓库里就跑仓库的 `data/vault.pmv`"的分支，已删除。它按
    「包装在哪」而不是「你在哪」来判断，结果是同一个命令在仓库内敲和在别处敲会解析
    到两个不同的库——`uv run pm import <导出文件>` 会静默造出第二个真库。

    密码库必须"一个命令一个库"。仓库外的位置也更安全：`data/` 被 `.gitignore`
    保护不被提交，但同样的忽略规则使它成了清理时无所谓的目录，`git clean -xfd`
    或一次删仓库就会连库一起带走。

    需要别的路径时用 `--vault` / `PM_VAULT` / `PM_HOME` 显式指定。
    """
    home = os.environ.get("PM_HOME")
    if home:
        return Path(home).expanduser() / "vault.pmv"
    return Path.home() / ".pm" / "vault.pmv"


class Vault:
    """一个加密保险库。未解锁时除 `exists` 外一切操作都拒绝执行。"""

    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path) if path else default_vault_path()
        self._key: bytes | None = None
        self._data: dict | None = None
        #: 上一次 unlock 的钥匙串写入结果。None = 没尝试，False = 尝试了但失败。
        #: 调用方据此提示用户"为什么这次还要输密码"，否则失败是完全静默的。
        self.last_cache_ok: bool | None = None

    # ── 状态 ────────────────────────────────────────────────────────────────

    @property
    def exists(self) -> bool:
        return self.path.exists()

    @property
    def unlocked(self) -> bool:
        return self._key is not None and self._data is not None

    @property
    def backup_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".bak")

    def _require_unlocked(self) -> dict:
        if not self.unlocked:
            raise VaultError("保险库尚未解锁。")
        return self._data  # type: ignore[return-value]

    def lock(self) -> None:
        """清除内存中的密钥与明文数据。"""
        self._key = None
        self._data = None

    # ── 创建 / 解锁 ─────────────────────────────────────────────────────────

    def create(self, password: str, *, meta: dict | None = None, force: bool = False) -> None:
        """创建空保险库。已存在且未指定 force 时报错。"""
        if self.path.exists() and not force:
            raise VaultError(f"保险库已存在：{self.path}（如需覆盖请显式指定 force）")
        if not password:
            raise VaultError("主密码不能为空。")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data = {
            "version": VAULT_FORMAT_VERSION,
            "created_at": now_ts(),
            "updated_at": now_ts(),
            "items": [],
            "meta": {"source": "created", **(meta or {})},
        }
        self._key = None
        # _write(password=...) 会生成新盐、派生新密钥并落盘
        self._write({}, password=password)
        # 创建完成后保持锁定状态，由调用方显式 unlock，避免"建完就开着"的隐式状态
        self._data = None
        self._key = None

    def set_password(self, old_password: str, new_password: str) -> None:
        """改主密码：用旧密码解锁后以新密码重写文件。"""
        self.unlock(old_password, use_cache=False)
        if not new_password:
            raise VaultError("新主密码不能为空。")
        self._write({}, password=new_password)

    def unlock(
        self,
        password: str,
        *,
        use_cache: bool = False,
        cache_ttl: int = KEYCHAIN_DEFAULT_TTL,
    ) -> None:
        """用主密码解锁，成功后按需写入钥匙串缓存。"""
        if not self.path.exists():
            raise VaultNotFound(f"保险库不存在：{self.path}")
        blob = self.path.read_bytes()
        header = parse_header(blob)
        key = derive_key(
            password,
            header.salt,
            iterations=header.iterations,
            memory_cost=header.memory_cost,
            lanes=header.lanes,
        )
        self._data = decrypt_payload(blob, key)
        self._key = key
        if use_cache:
            self.last_cache_ok = keychain_store(str(self.path), key, ttl=cache_ttl)
        else:
            self.last_cache_ok = None

    def unlock_cached(self, *, clear_on_failure: bool = True) -> bool:
        """尝试用钥匙串里的缓存密钥解锁。成功返回 True。

        缓存失效、过期或密钥不匹配（GCM 认证失败）都会清理缓存并返回 False，
        由调用方回落到交互式输入。
        """
        if not self.path.exists():
            return False
        cached = keychain_load(str(self.path))
        if cached is None:
            return False
        try:
            self._data = decrypt_payload(self.path.read_bytes(), cached)
        except (VaultError, OSError):
            if clear_on_failure:
                keychain_clear(str(self.path))
            return False
        self._key = cached
        # 命中缓存说明仍在有效期内，顺带把有效期往后推
        keychain_store(str(self.path), cached)
        return True

    def clear_cached_key(self) -> None:
        """清除钥匙串缓存（`pm lock`）。"""
        keychain_clear(str(self.path))

    # ── 落盘 ────────────────────────────────────────────────────────────────

    def save(self) -> None:
        """把当前内存状态整体加密落盘。"""
        self._require_unlocked()
        self._write({})

    def _write(self, extra_meta: dict, password: str | None = None) -> None:
        """原子写盘。password 给定时以该密码重新派生密钥（创建/改密路径）。"""
        data = self._require_unlocked() if password is None else self._data
        assert data is not None
        data["updated_at"] = now_ts()
        if extra_meta:
            data.setdefault("meta", {}).update(extra_meta)

        if password is not None:
            salt = os.urandom(16)
            key = derive_key(password, salt)
        else:
            key = self._key
            assert key is not None
            salt = parse_header(self.path.read_bytes()).salt

        blob = encrypt_with_salt(data, key, salt)
        self.path.parent.mkdir(parents=True, exist_ok=True)

        existed = self.path.exists()
        if existed:
            try:
                shutil.copy2(self.path, self.backup_path)
            except OSError:
                pass

        fd, tmp_name = tempfile.mkstemp(dir=str(self.path.parent), prefix=".pm-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

        if password is not None:
            self._key = key

        # 备份在落盘之后做：复制的是这次的新状态，失败也不影响已经写好的库。
        # 首次创建（原本不存在）不备份——一个空库没什么好留的，还会在 init 之后
        # 立刻产生一堆无意义副本。
        if existed:
            auto_backup(self.path)

    # ── 读取 ────────────────────────────────────────────────────────────────

    def all_items(self, *, include_archived: bool = True) -> list[Item]:
        """全部条目。"""
        data = self._require_unlocked()
        items = [Item.from_dict(raw) for raw in data.get("items", [])]
        if not include_archived:
            items = [i for i in items if not i.archived]
        return items

    def count(self) -> int:
        return len(self._require_unlocked().get("items", []))

    def filter(
        self,
        *,
        query: str = "",
        category: str = "",
        tag: str = "",
        include_archived: bool = False,
        favorites_only: bool = False,
        sort: str = "smart",
    ) -> list[Item]:
        """按条件筛选。category 可传 slug 或中文分类名。"""
        items = self.all_items(include_archived=include_archived)
        out: list[Item] = []
        for item in items:
            if favorites_only and not item.favorite:
                continue
            if category and not _category_matches(item, category):
                continue
            if tag and tag.lower() not in [t.lower() for t in item.tags]:
                continue
            if not item.matches(query):
                continue
            out.append(item)
        return _sort_items(out, sort)

    def resolve(self, key: str) -> Item:
        """把用户给的关键词解析成唯一条目。

        依次尝试：完整 id → 完整标题（不分大小写）→ 唯一 id 前缀 →
        slug 化标题 → 子串命中（唯一才通过）。

        **归档条目只在软查询的同一层里排活跃条目之后**：某一层里只要有活跃命中，
        归档就不进候选；一层里全是归档才退回去用归档。否则归档条目会占掉候选
        名额，让 `get` 数出来的条数和 `search`（默认不含归档）对不上——用户会
        看到一堆在搜索结果里根本不存在、也无法判断该选哪一条的候选。
        完整 id 是硬指针，归档也照取不误（归档要查内容才能决定删还是恢复）。
        """
        if not key:
            raise ItemNotFound(key)
        items = self.all_items()
        for item in items:
            if item.id == key:
                return item

        lowered = key.lower()
        slug = slugify(key)
        tiers = [
            [i for i in items if i.title.lower() == lowered],
            [i for i in items if i.id.startswith(key)],
            [i for i in items if slugify(i.title) == slug],
            [i for i in items if i.matches(key) or lowered in i.title.lower()],
        ]
        # 每层先算「活跃优先」后的命中集，再逐层看能不能收敛到唯一
        hits = []
        for tier in tiers:
            active = [i for i in tier if not i.archived]
            hits.append(active or tier)

        for tier in hits:
            if len(tier) == 1:
                return tier[0]

        candidates = hits[-1]
        if not candidates:
            raise ItemNotFound(key)
        # 标题精确命中多于一条时用那一层：比子串命中更贴近用户的意思
        raise AmbiguousItem(key, hits[0] if len(hits[0]) > 1 else candidates)

    def get(self, item_id: str) -> Item:
        """按 id 精确取条目。"""
        for item in self.all_items():
            if item.id == item_id:
                return item
        raise ItemNotFound(item_id)

    def tags(self, *, include_archived: bool = False) -> list[tuple[str, int]]:
        """全部标签及计数，按计数降序。"""
        counts: dict[str, int] = {}
        for item in self.all_items(include_archived=include_archived):
            for tag in item.tags:
                counts[tag] = counts.get(tag, 0) + 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))

    def stats(self) -> dict:
        """保险库概况。"""
        data = self._require_unlocked()
        items = [Item.from_dict(raw) for raw in data.get("items", [])]
        categories: dict[str, int] = {}
        for item in items:
            categories[item.category_name] = categories.get(item.category_name, 0) + 1
        return {
            "path": str(self.path),
            "items": len(items),
            "active": sum(1 for i in items if not i.archived),
            "archived": sum(1 for i in items if i.archived),
            "favorites": sum(1 for i in items if i.favorite),
            "with_password": sum(1 for i in items if i.secret_value),
            "tags": len({t for i in items for t in i.tags}),
            "categories": dict(sorted(categories.items(), key=lambda kv: -kv[1])),
            "created_at": data.get("created_at", 0),
            "updated_at": data.get("updated_at", 0),
            "size_bytes": self.path.stat().st_size if self.path.exists() else 0,
            "meta": data.get("meta", {}),
        }

    # ── 写入 ────────────────────────────────────────────────────────────────

    def add(self, item: Item) -> Item:
        """新增条目。会产生 payload 层面的 id 冲突检查。"""
        data = self._require_unlocked()
        if any(raw.get("id") == item.id for raw in data["items"]):
            item.id = new_id()
        stamp = now_ts()
        item.created_at = item.created_at or stamp
        item.updated_at = stamp
        if item.category_uuid and not item.category:
            item.category = category_by_slug("login").slug
        data["items"].append(item.to_dict())
        return item

    def create_item(
        self,
        title: str,
        *,
        category: str = "login",
        username: str = "",
        password: str = "",
        url: str = "",
        notes: str = "",
        tags: list[str] | None = None,
        fields: list[Field] | None = None,
        otp: str = "",
        save: bool = True,
    ) -> Item:
        """按字段直接建条目（CLI / Web 的共用入口）。"""
        spec = category_by_slug(category)
        item = Item(
            id=new_id(),
            title=title.strip() or "未命名条目",
            category=spec.slug,
            category_uuid=spec.uuid,
            username=username,
            password=password,
            otp=otp,
            urls=[{"label": "website", "url": url, "primary": True}] if url else [],
            tags=list(tags or []),
            notes=notes,
            fields=list(fields or []),
            source="manual",
        )
        self.add(item)
        if save:
            self.save()
        return item

    def update(self, item_id: str, patch: dict, *, save: bool = True) -> Item:
        """局部更新条目字段。password 变更时自动写入历史。"""
        data = self._require_unlocked()
        for index, raw in enumerate(data["items"]):
            if raw.get("id") != item_id:
                continue
            item = Item.from_dict(raw)

            if "password" in patch and patch["password"] != item.password and item.password:
                history = list(item.password_history)
                history.insert(0, {"value": item.password, "time": now_ts()})
                item.password_history = history[:20]

            if "url" in patch:
                url = patch.pop("url")
                item.urls = [{"label": "website", "url": url, "primary": True}] if url else []

            for key, value in patch.items():
                if key == "title" and isinstance(value, str):
                    item.title = value.strip() or item.title
                elif key == "category" and value:
                    spec = category_by_slug(str(value))
                    item.category = spec.slug
                    item.category_uuid = spec.uuid
                elif key == "tags":
                    item.tags = [str(t) for t in (value or [])]
                elif key == "fields":
                    item.fields = [
                        f if isinstance(f, Field) else Field.from_dict(f) for f in (value or [])
                    ]
                elif hasattr(item, key):
                    setattr(item, key, value)

            item.updated_at = now_ts()
            data["items"][index] = item.to_dict()
            if save:
                self.save()
            return item
        raise ItemNotFound(item_id)

    def delete(self, item_id: str, *, save: bool = True) -> Item:
        """删除条目并返回被删对象。"""
        data = self._require_unlocked()
        for index, raw in enumerate(data["items"]):
            if raw.get("id") == item_id:
                removed = Item.from_dict(raw)
                data["items"].pop(index)
                if save:
                    self.save()
                return removed
        raise ItemNotFound(item_id)

    # ── 导入合并 ────────────────────────────────────────────────────────────

    def merge(
        self,
        incoming: list[Item],
        *,
        overwrite: bool = False,
        save: bool = True,
    ) -> MergeResult:
        """合并导入的条目。

        幂等键优先级：`source:source_id` → `标题 + 用户名`。命中已存在的条目时，
        默认跳过（`overwrite=True` 则用新数据覆盖，同时保留本地密码历史）。
        """
        data = self._require_unlocked()
        index: dict[str, int] = {}
        for position, raw in enumerate(data["items"]):
            index[_merge_key(raw.get("source", ""), raw.get("source_id", ""),
                             raw.get("title", ""), raw.get("username", ""))] = position

        result = MergeResult()
        for item in incoming:
            key = _merge_key(item.source, item.source_id, item.title, item.username)
            position = index.get(key)
            if position is None:
                item.id = new_id(item.source_id or f"{item.title}|{item.username}")
                while any(raw.get("id") == item.id for raw in data["items"]):
                    item.id = new_id(f"{item.id}{now_ts()}")
                data["items"].append(item.to_dict())
                index[key] = len(data["items"]) - 1
                result.added += 1
                continue

            if not overwrite:
                result.skipped += 1
                continue

            existing = Item.from_dict(data["items"][position])
            history = list(existing.password_history)
            if existing.password and existing.password != item.password:
                history.insert(0, {"value": existing.password, "time": now_ts()})
            item.password_history = (history + list(item.password_history))[:20]
            item.id = existing.id
            item.created_at = existing.created_at or item.created_at
            item.favorite = item.favorite or existing.favorite
            item.tags = sorted({*existing.tags, *item.tags})
            item.updated_at = now_ts()
            data["items"][position] = item.to_dict()
            result.updated += 1

        if save and (result.added or result.updated):
            self.save()
        return result

    # ── 导入 / 导出 ─────────────────────────────────────────────────────────

    def import_file(
        self,
        source: str | os.PathLike,
        *,
        overwrite: bool = False,
        include_archived: bool = True,
    ) -> MergeResult:
        """导入 .1pux 或 .csv 文件。"""
        from .importer import load_any

        items, meta = load_any(source, include_archived=include_archived)
        result = self.merge(items, overwrite=overwrite)
        data = self._require_unlocked()
        data.setdefault("meta", {}).update(
            {k: v for k, v in meta.items() if k in ("source", "source_account", "last_import_at")}
        )
        data["meta"]["last_import_count"] = result.total
        if result.total:
            self.save()
        return result

    def export_payload(self, *, reveal: bool = False) -> dict:
        """导出为明文 JSON 结构。reveal=False 时打码所有密文字段。"""
        data = self._require_unlocked()
        payload = {
            "version": data.get("version", VAULT_FORMAT_VERSION),
            "exported_at": now_ts(),
            "meta": data.get("meta", {}),
            "items": [],
        }
        for raw in data.get("items", []):
            entry = dict(raw)
            if not reveal:
                for key in ("password", "otp"):
                    if entry.get(key):
                        entry[key] = "••••••••"
                entry["fields"] = [
                    {**f, "value": "••••••••"} if f.get("secret") else f
                    for f in entry.get("fields", [])
                ]
                entry["password_history"] = [
                    {**h, "value": "••••••••"} for h in entry.get("password_history", [])
                ]
            payload["items"].append(entry)
        return payload

    def export_json(self, target: str | os.PathLike, *, reveal: bool = False) -> Path:
        """导出 JSON 到文件（权限 0600）。"""
        out = Path(target)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self.export_payload(reveal=reveal), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.chmod(out, 0o600)
        return out


# ── 内部工具 ─────────────────────────────────────────────────────────────────


def _merge_key(source: str, source_id: str, title: str, username: str) -> str:
    if source_id:
        return f"{source}:{source_id}"
    return f"t:{title.strip().lower()}|{username.strip().lower()}"


def _category_matches(item: Item, wanted: str) -> bool:
    needle = wanted.strip().lower()
    return needle in {
        item.category.lower(),
        item.category_uuid.lower(),
        item.category_name.lower(),
        category_by_slug(item.category).name_en.lower(),
    }


def _sort_items(items: list[Item], mode: str) -> list[Item]:
    if mode == "title":
        return sorted(items, key=lambda i: i.title.lower())
    if mode == "updated":
        return sorted(items, key=lambda i: -(i.updated_at or 0))
    if mode == "created":
        return sorted(items, key=lambda i: -(i.created_at or 0))
    if mode == "category":
        return sorted(items, key=lambda i: (i.category_name, i.title.lower()))
    return sorted(items, key=Item.sort_key)
