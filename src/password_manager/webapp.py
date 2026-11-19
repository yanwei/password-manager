"""Web 模式 —— 本地 Flask 应用，提供完整的增删改查界面。

安全边界（都是刻意的取舍，不是省事）
------------------------------------
* **只监听 127.0.0.1**：不提供把保险库暴露到局域网的开关。真有远程需求请自己
  套 SSH 隧道（`ssh -L 8848:127.0.0.1:8848 host`），而不是把服务挂到 0.0.0.0。
* **解锁密钥只存在服务端进程内存里**，不进 cookie、不写磁盘。浏览器手里只有一个
  随机 CSRF token，读接口也要带它——跨站页面拿不到 token，因此无法通过你的浏览器
  驱动这个服务。
* **空闲自动锁定**：每次请求刷新活跃时间，超过阈值就清掉内存里的密钥。校验是惰性的
  （下一次请求时判断），比后台线程更可靠。
* **明文只在显式请求时才出内存**：`/api/items` 列表永远不含密文；单条明细要带
  `?reveal=1` 才返回明文，且响应标记 `Cache-Control: no-store`。
"""

from __future__ import annotations

import os
import secrets
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

from . import APP_TITLE, DEFAULT_IDLE_LOCK, __version__
from . import backup as backup_mod
from .audit import ISSUE_LABELS, audit, evaluate
from .crypto import VaultError, WrongPassword, keychain_available, keychain_load
from .models import Field, all_categories, category_by_slug
from .ui import generate_password
from .vault import AmbiguousItem, ItemNotFound, Vault

#: 上传导入的体积上限（1PUX 通常几百 KB）
MAX_UPLOAD_BYTES = 64 * 1024 * 1024


def _backup_note() -> dict | None:
    """取出本次写操作触发的自动备份结果（取过即清），塞进响应给前端弹提示。"""
    result = backup_mod.take_notice()
    return result.to_dict() if result else None


class WebState:
    """Web 服务的单例状态。所有写操作都在 `lock` 内串行化。"""

    def __init__(self, vault_path: str, idle_lock: int):
        self.vault = Vault(vault_path)
        self.idle_lock = max(60, int(idle_lock))
        self.token = secrets.token_urlsafe(32)
        self.last_seen = time.time()
        self.unlocked_at = 0.0
        self.lock = threading.RLock()
        self.import_notes: list[str] = []

    # ── 状态 ────────────────────────────────────────────────────────────────

    @property
    def unlocked(self) -> bool:
        return self.vault.unlocked

    def idle_for(self) -> float:
        return time.time() - self.last_seen

    def touch(self) -> None:
        self.last_seen = time.time()

    def expire_if_idle(self) -> bool:
        """超过空闲阈值就锁定。返回是否刚刚发生了锁定。"""
        if self.unlocked and self.idle_for() > self.idle_lock:
            self.lock_now()
            return True
        return False

    def lock_now(self) -> None:
        self.vault.lock()
        self.token = secrets.token_urlsafe(32)
        self.unlocked_at = 0.0

    def try_cache(self) -> bool:
        """尝试用钥匙串里的缓存密钥自动解锁。"""
        if self.vault.unlock_cached():
            self.unlocked_at = time.time()
            return True
        return False

    def cached_key_available(self) -> bool:
        """钥匙串里是否真有一把仍有效、且属于本库的缓存密钥。

        只在渲染解锁页时调用一次。刻意不放进 /api/status —— 那个接口被前端每 5 秒
        ping 一次，而这里每调一次都要起一个 `security` 子进程，放进去等于每 5 秒
        拉一个进程起来。
        """
        if not self.vault.exists:
            return False
        return keychain_load(str(self.vault.path)) is not None

    def unlock(self, password: str, *, cache: bool = True) -> None:
        self.vault.unlock(password, use_cache=cache)
        self.unlocked_at = time.time()

    def status(self) -> dict:
        payload = {
            "unlocked": self.unlocked,
            "idle_lock": self.idle_lock,
            "idle_for": int(self.idle_for()),
            "token": self.token if self.unlocked else "",
            "vault": str(self.vault.path),
            "version": __version__,
            "app": APP_TITLE,
            "keychain": keychain_available(),
        }
        if self.unlocked:
            stats = self.vault.stats()
            payload["items"] = stats["items"]
            payload["active"] = stats["active"]
            payload["archived"] = stats["archived"]
            payload["categories"] = stats["categories"]
        return payload


# ── 序列化 ───────────────────────────────────────────────────────────────────


def item_brief(item) -> dict:
    """列表项：永远不含任何密文。"""
    return {
        "id": item.id,
        "title": item.title,
        "category": item.category,
        "category_name": item.category_name,
        "username": item.username,
        "url": item.primary_url,
        "host": item.host,
        "tags": item.tags,
        "favorite": item.favorite,
        "archived": item.archived,
        "updated_at": item.updated_at,
        "has_secret": item.has_secret,
        "secret_label": item.secret_label,
        "secret_count": item.secret_field_count,
    }


def item_detail(item, *, reveal: bool) -> dict:
    """单条明细。

    不 reveal 时，密文字段的 value 直接返回空串（不是打码后的假值）——前端拿不到
    明文就不可能因为一个渲染 bug 把它漏出来。reveal 时把 revealed 标记为真，
    前端只负责切换显示与否。
    """
    rows = []
    for label, value, secret in item.display_fields():
        row = {"label": label, "value": "", "secret": secret, "revealed": False, "link": ""}
        if secret:
            if reveal:
                row["value"] = value
                row["revealed"] = True
        else:
            row["value"] = value
            if value.startswith(("http://", "https://")):
                row["link"] = value
        rows.append(row)

    form_rows = []
    for label, value, secret in item.web_form_rows():
        form_rows.append(
            {
                "label": label,
                "value": value if (reveal or not secret) else "",
                "secret": secret,
            }
        )

    payload = {
        **item_brief(item),
        "vault": item.vault,
        "created_at": item.created_at,
        "notes": item.notes,
        "urls": item.urls,
        "fields": rows,
        "form_rows": form_rows,
        "attachments": [
            {
                "name": a.get("name", ""),
                "size": a.get("size", 0),
                "inline": a.get("inline", False),
                "too_large": a.get("too_large", False),
            }
            for a in item.attachments
        ],
        # 历史密码只在 reveal 时给出明文，否则只给时间线骨架
        "history": [
            {
                "time": h.get("time", 0),
                "value": str(h.get("value", "")) if reveal else "",
            }
            for h in item.password_history
        ],
        "strength": _strength(item.secret_value),
    }
    return payload


def _strength(password: str) -> dict | None:
    """强度信息。不泄露明文，因此不 reveal 时也照常返回——就像密码强度条。"""
    if not password:
        return None
    result = evaluate(password)
    return {
        "score": result.score,
        "label": result.label,
        "bits": result.bits,
        "warnings": result.warnings,
    }


# ── 应用工厂 ─────────────────────────────────────────────────────────────────


def create_app(vault_path: str, idle_lock: int = DEFAULT_IDLE_LOCK) -> Flask:
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.config["JSON_AS_ASCII"] = False
    state = WebState(vault_path, idle_lock)
    app.extensions["pm_state"] = state

    # ── 中间件 ──────────────────────────────────────────────────────────────

    @app.after_request
    def _no_store(response):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.before_request
    def _guard():
        state.expire_if_idle()
        if request.method == "OPTIONS":
            return None
        if request.path.startswith("/api/"):
            # 只接受同源请求；跨站页面的 Origin 一定不同
            origin = request.headers.get("Origin")
            if origin:
                allowed = {f"http://{h}" for h in ("127.0.0.1", "localhost", "[::1]")}
                allowed |= {f"http://127.0.0.1:{request.host.split(':')[-1]}"}
                if not any(origin.startswith(a) for a in allowed):
                    return jsonify({"error": "拒绝跨站请求。"}), 403
            state.touch()
            if request.path in ("/api/status", "/api/unlock"):
                return None
            token = request.headers.get("X-PM-Token") or request.args.get("token", "")
            if not state.unlocked:
                return jsonify({"error": "保险库已锁定，请重新解锁。", "locked": True}), 401
            if not secrets.compare_digest(token, state.token):
                return jsonify({"error": "会话令牌无效，请刷新页面。", "locked": True}), 401
        return None

    @app.errorhandler(404)
    def _not_found(_exc):
        if request.path.startswith("/api/"):
            return jsonify({"error": "接口不存在。"}), 404
        return (
            render_template(
                "login.html",
                app_title=APP_TITLE,
                version=__version__,
                cache_available=state.cached_key_available(),
            ),
            404,
        )

    @app.errorhandler(VaultError)
    def _vault_error(exc):
        return jsonify({"error": str(exc)}), 400

    @app.errorhandler(ItemNotFound)
    def _missing(exc):
        return jsonify({"error": str(exc)}), 404

    @app.errorhandler(AmbiguousItem)
    def _ambiguous(exc):
        return jsonify({"error": str(exc)}), 409

    # ── 页面 ────────────────────────────────────────────────────────────────

    @app.get("/")
    def index():
        if not state.unlocked:
            # 「用缓存解锁」是否显示由服务端一次性决定：交给 JS 在加载后再插入，
            # 卡片会因为多出一行而重新居中，视觉上就是"先居中再往上蹿一下"。
            return render_template(
                "login.html",
                app_title=APP_TITLE,
                version=__version__,
                cache_available=state.cached_key_available(),
            )
        return render_template(
            "index.html",
            app_title=APP_TITLE,
            version=__version__,
            token=state.token,
            idle_lock=state.idle_lock,
        )

    # ── 会话 ────────────────────────────────────────────────────────────────

    @app.get("/api/status")
    def api_status():
        return jsonify(state.status())

    @app.post("/api/unlock")
    def api_unlock():
        payload = request.get_json(silent=True) or {}
        password = str(payload.get("password") or "")
        cache = bool(payload.get("cache", True))
        if not state.vault.exists:
            return jsonify({"error": f"保险库不存在：{state.vault.path}"}), 400
        with state.lock:
            if not password and cache and state.try_cache():
                return jsonify({**state.status(), "via": "keychain"})
            if not password:
                return jsonify({"error": "请输入主密码。"}), 400
            try:
                state.unlock(password, cache=cache)
            except WrongPassword:
                return jsonify({"error": "主密码错误。"}), 401
            except VaultError as exc:
                return jsonify({"error": str(exc)}), 400
        return jsonify({**state.status(), "via": "password"})

    @app.post("/api/lock")
    def api_lock():
        with state.lock:
            state.lock_now()
        return jsonify({"ok": True})

    # ── 列表 / 明细 ─────────────────────────────────────────────────────────

    @app.get("/api/items")
    def api_items():
        include_archived = request.args.get("archived", "0") == "1"
        sort = request.args.get("sort", "smart")
        with state.lock:
            items = state.vault.filter(
                query=request.args.get("q", ""),
                category=request.args.get("cat", ""),
                tag=request.args.get("tag", ""),
                include_archived=include_archived,
                favorites_only=request.args.get("fav", "0") == "1",
                sort=sort,
            )
            return jsonify({"count": len(items), "items": [item_brief(i) for i in items]})

    @app.get("/api/items/<item_id>")
    def api_item(item_id: str):
        reveal = request.args.get("reveal", "0") == "1"
        with state.lock:
            item = state.vault.get(item_id)
            return jsonify(item_detail(item, reveal=reveal))

    @app.post("/api/items")
    def api_create():
        payload = request.get_json(silent=True) or {}
        title = str(payload.get("title") or "").strip()
        if not title:
            return jsonify({"error": "标题不能为空。"}), 400
        password = payload.get("password")
        if payload.get("generate") or password is None:
            password = generate_password(int(payload.get("length") or 20))
        fields = [
            Field(
                title=str(f.get("title") or "").strip() or "字段",
                value=str(f.get("value") or ""),
                kind="concealed" if f.get("secret") else "string",
                secret=bool(f.get("secret")),
                section=str(f.get("section") or ""),
            )
            for f in (payload.get("fields") or [])
            if isinstance(f, dict) and (f.get("title") or f.get("value"))
        ]
        with state.lock:
            backup_mod.clear_notice()
            item = state.vault.create_item(
                title,
                category=str(payload.get("category") or "login"),
                username=str(payload.get("username") or ""),
                password=str(password or ""),
                url=str(payload.get("url") or ""),
                notes=str(payload.get("notes") or ""),
                tags=[str(t) for t in (payload.get("tags") or [])],
                fields=fields,
                otp=str(payload.get("otp") or ""),
            )
            return jsonify(
                {"ok": True, "item": item_detail(item, reveal=True), "backup": _backup_note()}
            ), 201

    @app.patch("/api/items/<item_id>")
    def api_update(item_id: str):
        payload = request.get_json(silent=True) or {}
        patch: dict = {}
        for key in ("title", "username", "url", "notes", "otp"):
            if key in payload:
                patch[key] = str(payload[key] or "")
        if "password" in payload and payload["password"]:
            patch["password"] = str(payload["password"])
        if payload.get("generate"):
            patch["password"] = generate_password(int(payload.get("length") or 20))
        if "category" in payload and payload["category"]:
            patch["category"] = str(payload["category"])
        if "tags" in payload:
            patch["tags"] = [str(t) for t in (payload["tags"] or [])]
        if "favorite" in payload:
            patch["favorite"] = bool(payload["favorite"])
        if "archived" in payload:
            patch["archived"] = bool(payload["archived"])
        if not patch:
            return jsonify({"error": "没有提交任何可修改字段。"}), 400
        with state.lock:
            backup_mod.clear_notice()
            updated = state.vault.update(item_id, patch)
            return jsonify(
                {
                    "ok": True,
                    "item": item_detail(updated, reveal="password" in patch),
                    "generated": patch.get("password") if payload.get("generate") else None,
                    "backup": _backup_note(),
                }
            )

    @app.delete("/api/items/<item_id>")
    def api_delete(item_id: str):
        with state.lock:
            backup_mod.clear_notice()
            removed = state.vault.delete(item_id)
            return jsonify(
                {
                    "ok": True,
                    "title": removed.title,
                    "count": state.vault.count(),
                    "backup": _backup_note(),
                }
            )

    # ── 元信息 ──────────────────────────────────────────────────────────────

    @app.get("/api/meta")
    def api_meta():
        include_archived = request.args.get("archived", "0") == "1"
        with state.lock:
            tags = state.vault.tags(include_archived=include_archived)
            items = state.vault.all_items(include_archived=include_archived)
            counts: dict[str, int] = {}
            for item in items:
                counts[item.category] = counts.get(item.category, 0) + 1
            return jsonify(
                {
                    "tags": [{"tag": t, "count": c} for t, c in tags],
                    "categories": [
                        {
                            "uuid": spec.uuid,
                            "slug": spec.slug,
                            "name": spec.name_zh,
                            "name_en": spec.name_en,
                            "count": counts.get(spec.slug, 0),
                        }
                        for spec in all_categories()
                    ],
                    "field_kinds": ["string", "secret"],
                }
            )

    @app.post("/api/gen")
    def api_gen():
        payload = request.get_json(silent=True) or {}
        passwords = [
            generate_password(
                int(payload.get("length") or 20),
                symbols=bool(payload.get("symbols", True)),
                digits=bool(payload.get("digits", True)),
                upper=bool(payload.get("upper", True)),
                lower=bool(payload.get("lower", True)),
                avoid_ambiguous=bool(payload.get("avoid_ambiguous", False)),
            )
            for _ in range(min(max(int(payload.get("count") or 1), 1), 20))
        ]
        return jsonify({"passwords": [{"value": p, "strength": _strength(p)} for p in passwords]})

    @app.get("/api/audit")
    def api_audit():
        with state.lock:
            report = audit(state.vault.all_items(include_archived=request.args.get("archived") == "1"))
            return jsonify(
                {
                    "health": report.health,
                    "total": report.total,
                    "archived": report.archived,
                    "with_password": report.with_password,
                    "with_history": report.with_history,
                    "histogram": report.score_histogram,
                    "counts": {k: len(v) for k, v in report.by_kind.items()},
                    "labels": ISSUE_LABELS,
                    "findings": [
                        {
                            "kind": f.kind,
                            "label": f.label,
                            "title": f.title,
                            "item_id": f.item_id,
                            "detail": f.detail,
                        }
                        for f in report.findings
                    ],
                }
            )

    # ── 导入 / 导出 ─────────────────────────────────────────────────────────

    @app.get("/api/export")
    def api_export():
        reveal = request.args.get("reveal") == "1"
        target = state.vault.path.parent / "export.json"
        with state.lock:
            path = state.vault.export_json(target, reveal=reveal)
            return send_file(
                path,
                as_attachment=True,
                download_name=f"pm-export-{'plain' if reveal else 'masked'}.json",
                mimetype="application/json",
            )

    @app.post("/api/import")
    def api_import():
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            return jsonify({"error": "没有收到文件。"}), 400
        suffix = Path(upload.filename).suffix.lower()
        if suffix not in (".1pux", ".pux", ".csv", ".json"):
            return jsonify({"error": f"不支持的文件类型：{suffix or upload.filename}"}), 400

        staging = state.vault.path.parent / f".upload-{secrets.token_hex(6)}{suffix}"
        staging.parent.mkdir(parents=True, exist_ok=True)
        upload.save(staging)
        try:
            with state.lock:
                backup_mod.clear_notice()
                result = state.vault.import_file(
                    staging, overwrite=request.form.get("overwrite") == "1"
                )
                backup = _backup_note()
            return jsonify(
                {
                    "ok": True,
                    "added": result.added,
                    "updated": result.updated,
                    "skipped": result.skipped,
                    "count": state.vault.count(),
                    "file": upload.filename,
                    "backup": backup,
                }
            )
        finally:
            try:
                os.unlink(staging)
            except OSError:
                pass

    return app
