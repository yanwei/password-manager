"""密文备份 —— 把 vault.pmv 复制一份到别处，只搬字节，不碰密钥。

三条设计约束
------------
* **不需要主密码**。备份对象已经是 AES-256-GCM 密文，复制它不需要任何密钥，
  于是备份路径上不存在"云端凭据能碰到解锁材料"的问题——这是选文件复制而不是
  "云端同步"的主要原因。
* **只往外复制，不做双向同步**。主库永远只有 `~/.pm/vault.pmv` 一个。把主路径
  指到 iCloud Drive 会同时引入三个坑：文件被"优化存储"变成 dataless 占位符后
  离线读不到、File Provider 的异步语义破坏 `os.replace` 的原子性、两台机器同指
  一个文件时整包互相覆盖。所以这里只做单向副本。
* **失败绝不回滚已经成功的写操作**。备份在保险库落盘之后才执行，任何异常都被
  收进 `BackupResult.error` 交给上层提示，不抛给调用方。

备份文件名里带时间戳（`pm-YYYYMMDD-HHMMSS.pmv`），按名字排序即按时间排序，
轮转只认这个模式——目录里别的手工文件一律不碰。
"""

from __future__ import annotations

import hashlib
import os
import shutil
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

#: 备份文件命名模式。轮转只删匹配它的文件
PREFIX = "pm-"
SUFFIX = ".pmv"

#: 默认保留份数。一份约 145 KB，30 份 ≈ 4 MB，够回滚一个月内的误操作
DEFAULT_KEEP = 30

#: iCloud Drive 在本机的挂载点。注意它与「桌面与文稿」同步无关，这里只认 CloudDocs 根
ICLOUD_FOLDER = ("Library", "Mobile Documents", "com~apple~CloudDocs")

#: 放在 iCloud Drive 里的子目录名
ICLOUD_SUBDIR = "pm-backup"


# ── 结果 ─────────────────────────────────────────────────────────────────────


@dataclass
class BackupResult:
    """一次备份的结果。`ok=False` 时只有 `error` 有意义。"""

    ok: bool
    dir: Path | None = None
    file: Path | None = None
    label: str = ""
    bytes: int = 0
    digest: str = ""
    kept: int = 0
    removed: int = 0
    error: str = ""

    @property
    def filename(self) -> str:
        return self.file.name if self.file else ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "dir": str(self.dir) if self.dir else "",
            "file": str(self.file) if self.file else "",
            "filename": self.filename,
            "label": self.label,
            "bytes": self.bytes,
            "sha256": self.digest,
            "kept": self.kept,
            "removed": self.removed,
            "error": self.error,
        }

    def hint(self) -> str:
        """一行提示，CLI 与 Web 共用。"""
        if not self.ok:
            return f"自动备份失败：{self.error}"
        return f"已自动备份 → {self.filename}（{self.label} · 保留 {self.kept} 份）"


# ── 待提示的结果（线程局部） ─────────────────────────────────────────────────
#
# `Vault` 在写盘后把结果放进来，入口层（CLI main / Flask 请求）取走并提示。
# 用线程局部而非全局：Flask 开发服务器是多线程的，而"设置"和"取走"总在同一个
# 请求线程内完成。

_local = threading.local()


def _set_notice(result: BackupResult) -> None:
    _local.notice = result


def take_notice() -> BackupResult | None:
    """取走本次写操作触发的备份结果，取过即清。"""
    result = getattr(_local, "notice", None)
    _local.notice = None
    return result


def clear_notice() -> None:
    """丢弃残留结果。写操作开始前调用，避免线程复用把上一次的提示带过来。"""
    _local.notice = None


# ── 开关 ─────────────────────────────────────────────────────────────────────


def env_flag(name: str) -> bool:
    """环境变量是否被设为"真"。空字符串视为未设置。"""
    value = os.environ.get(name, "").strip().lower()
    return value not in ("", "0", "false", "no", "off")


_enabled = True


def set_enabled(flag: bool) -> None:
    """CLI `--no-backup` 走这里。"""
    global _enabled
    _enabled = bool(flag)


def enabled() -> bool:
    return _enabled and not env_flag("PM_NO_BACKUP")


# ── 位置 ─────────────────────────────────────────────────────────────────────


def icloud_drive_root() -> Path:
    """iCloud Drive 挂载点（不保证存在）。"""
    return Path.home().joinpath(*ICLOUD_FOLDER)


def default_backup_dir() -> Path:
    """备份目录：`PM_BACKUP_DIR` → iCloud Drive → `~/.pm/backup`。

    优先 iCloud Drive 是因为它同时满足"异地"和"零凭据"：不用申请 AK/SK，也不会
    把云账号的凭据变成保险库路径上的依赖。没有 iCloud 时退回本地目录，仍然是
    "误删/误覆盖可恢复"，只是防不了整机丢失。
    """
    custom = os.environ.get("PM_BACKUP_DIR")
    if custom:
        return Path(custom).expanduser()
    icloud = icloud_drive_root()
    if icloud.is_dir():
        return icloud / ICLOUD_SUBDIR
    return Path.home() / ".pm" / "backup"


def dir_label(path: Path) -> str:
    """给人看的目录名：能归到 iCloud Drive 或家目录就说得短一点。"""
    target = path.expanduser()
    try:
        rel = target.resolve().relative_to(icloud_drive_root().resolve())
    except (ValueError, OSError):
        pass
    else:
        return "iCloud Drive" if str(rel) in ("", ".") else f"iCloud Drive/{rel}"
    try:
        rel = target.resolve().relative_to(Path.home().resolve())
    except (ValueError, OSError):
        return str(target)
    return f"~/{rel}"


def keep_default() -> int:
    """保留份数，`PM_BACKUP_KEEP=0` 表示不限。"""
    raw = os.environ.get("PM_BACKUP_KEEP", "").strip()
    if not raw:
        return DEFAULT_KEEP
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_KEEP


# ── 备份 ─────────────────────────────────────────────────────────────────────


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def existing_backups(directory: Path) -> list[Path]:
    """目录里由本工具写出的备份，按时间升序（名字里的时间戳可字典序比较）。"""
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob(f"{PREFIX}*{SUFFIX}") if p.is_file())


def _unique_target(directory: Path, stamp: str) -> Path:
    """同一秒内写第二次时不覆盖第一次——两次内容本来就不同。"""
    target = directory / f"{PREFIX}{stamp}{SUFFIX}"
    index = 2
    while target.exists():
        target = directory / f"{PREFIX}{stamp}-{index}{SUFFIX}"
        index += 1
    return target


def prune(directory: Path, keep: int) -> tuple[int, int]:
    """只保留最新 `keep` 份，返回（删掉几份，剩几份）。keep<=0 表示不限。"""
    files = existing_backups(directory)
    if keep <= 0 or len(files) <= keep:
        return 0, len(files)
    removed = 0
    for stale in files[: len(files) - keep]:
        try:
            stale.unlink()
            removed += 1
        except OSError:
            pass
    return removed, len(files) - removed


def backup_once(
    source: str | os.PathLike,
    *,
    target_dir: str | os.PathLike | None = None,
    keep: int | None = None,
    now: datetime | None = None,
) -> BackupResult:
    """把 `source` 复制成一份带时间戳的备份。任何失败都收进返回值。"""
    src = Path(source).expanduser()
    directory = Path(target_dir).expanduser() if target_dir else default_backup_dir()
    label = dir_label(directory)
    limit = keep_default() if keep is None else max(0, int(keep))

    if not src.is_file():
        return BackupResult(ok=False, dir=directory, label=label, error=f"保险库不存在：{src}")

    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    try:
        directory.mkdir(parents=True, exist_ok=True)
        target = _unique_target(directory, stamp)
        shutil.copy2(src, target)
        os.chmod(target, 0o600)
        digest = sha256_file(target)
        if digest != sha256_file(src):
            # 副本与源不一致就别留着——一份不可靠的备份比没有备份更危险
            target.unlink(missing_ok=True)
            return BackupResult(
                ok=False, dir=directory, label=label, error="副本校验与源不一致，已丢弃"
            )
        removed, kept = prune(directory, limit)
    except OSError as exc:
        reason = exc.strerror or str(exc)
        return BackupResult(ok=False, dir=directory, label=label, error=f"{directory}：{reason}")

    return BackupResult(
        ok=True,
        dir=directory,
        file=target,
        label=label,
        bytes=target.stat().st_size,
        digest=digest,
        kept=kept,
        removed=removed,
    )


def auto_backup(source: str | os.PathLike) -> BackupResult | None:
    """写盘后的自动备份。返回 None 表示这次被开关关掉了（不是失败）。"""
    if not enabled():
        return None
    result = backup_once(source)
    _set_notice(result)
    return result
