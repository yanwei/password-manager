"""CLI 入口 —— `pm` 的全部子命令。

解锁策略
--------
1. 先试 macOS 钥匙串里的缓存密钥（15 分钟有效，命中即静默解锁）；
2. 缓存缺失/过期则提示输入主密码，成功后写入缓存；
3. `--no-cache` 完全绕过缓存，`pm lock` 立即清除。

缓存里存的是**派生后的密钥**而非主密码。缓存被窃取等于保险库被解锁，所以默认
15 分钟失效，且每次命中会把有效期往后推（连续操作不会中途掉线）。
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path

from . import APP_TITLE, DEFAULT_IDLE_LOCK, __version__
from . import backup as backup_mod
from .audit import ISSUE_LABELS, audit, evaluate
from .crypto import VaultError, WrongPassword, keychain_available
from .models import Item, all_categories, humanize, ts_to_date
from .ui import (
    Column,
    Style,
    clipboard_available,
    copy_to_clipboard,
    generate_password,
    heading,
    kv_block,
    mask_secret,
    render_table,
    truncate,
)
from .vault import AmbiguousItem, ItemNotFound, Vault, default_vault_path

PROG = "pm"

DEFAULT_KEEP = backup_mod.DEFAULT_KEEP

JSON_KW = {"ensure_ascii": False, "indent": 2}

#: 由 main() 按 --no-color / TTY 情况重新赋值，模块内所有输出都读这个
STYLE = Style()


# ── 输出 ─────────────────────────────────────────────────────────────────────


class Printer:
    """统一出口：JSON 模式下只吐结构化数据，否则吐人看的文本。"""

    def __init__(self, as_json: bool = False, quiet: bool = False, style: Style | None = None):
        self.json = as_json
        self.quiet = quiet
        self.style = style or STYLE

    def data(self, payload: object) -> None:
        if self.json:
            print(json.dumps(payload, **JSON_KW))

    def text(self, *lines: str) -> None:
        if not self.json and not self.quiet:
            print("\n".join(lines))

    def blank(self) -> None:
        if not self.json and not self.quiet:
            print()

    def warn(self, message: str) -> None:
        if not self.json and not self.quiet:
            print(f"{self.style.warn('!')} {message}", file=sys.stderr)

    def error(self, message: str) -> None:
        print(f"{self.style.bad('✗')} {message}", file=sys.stderr)


def _item_brief(item: Item) -> dict:
    return {
        "id": item.id,
        "title": item.title,
        "category": item.category,
        "category_name": item.category_name,
        "username": item.username,
        "url": item.primary_url,
        "tags": item.tags,
        "favorite": item.favorite,
        "archived": item.archived,
        "updated_at": item.updated_at,
        "has_secret": item.has_secret,
        "secret_label": item.secret_label,
        "secret_fields": item.secret_field_count,
    }


def _item_full(item: Item, *, reveal: bool = False, include_form: bool = False) -> dict:
    """明细结构。reveal=False 时密文一律打码。

    JSON 里有两个来源不同的列表，别混：
      * `fields`  —— 模型原始的自定义字段（`sections[].fields[]`）。普通 Login
        这里是空的，因为它的用户名/密码在顶层 `username`/`password` 上。
      * `rows`    —— 人看到的合成展示行，等于 CLI 文本视图的那张表。脚本想
        "跟人看到的一样" 就读 `rows`。
    """
    payload = item.to_dict()
    rows: list[dict] = []
    for label, value, secret in item.display_fields():
        masked = secret and not reveal
        rows.append(
            {
                "label": label,
                "value": mask_secret(value) if masked else value,
                "secret": secret,
                "masked": masked,
            }
        )
    payload["rows"] = rows

    if not reveal:
        for key in ("password", "otp"):
            if payload.get(key):
                payload[key] = mask_secret(payload[key])
        payload["fields"] = [
            {**f, "value": mask_secret(f["value"])} if f.get("secret") else f
            for f in payload.get("fields", [])
        ]
        payload["form_fields"] = [
            {**f, "value": mask_secret(f["value"])} if f.get("secret") else f
            for f in payload.get("form_fields", [])
        ]
        payload["password_history"] = [
            {**h, "value": mask_secret(h["value"])} for h in payload.get("password_history", [])
        ]
    payload["category_name"] = item.category_name
    payload["secret_label"] = item.secret_label
    payload["strength"] = _strength_payload(item.secret_value)
    if not include_form:
        payload.pop("form_fields", None)
    return payload


def _strength_payload(password: str) -> dict | None:
    if not password:
        return None
    result = evaluate(password)
    return {
        "score": result.score,
        "label": result.label,
        "bits": result.bits,
        "warnings": result.warnings,
    }


# ── 参数解析 ─────────────────────────────────────────────────────────────────


def _common_options() -> argparse.ArgumentParser:
    """所有子命令共享的全局开关。

    default=SUPPRESS 是刻意的：只有用户真的传了才会出现在 namespace 里，
    否则子解析器的默认值会覆盖掉主解析器上已经解析好的值。
    """
    parser = argparse.ArgumentParser(add_help=False)
    group = parser.add_argument_group("全局选项")
    group.add_argument(
        "--vault",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="保险库文件路径（默认 ~/.pm/vault.pmv；与在哪个目录调用无关）",
    )
    group.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="以 JSON 输出，便于脚本消费"
    )
    group.add_argument(
        "--no-color", action="store_true", default=argparse.SUPPRESS, help="关闭彩色输出"
    )
    group.add_argument(
        "--no-cache",
        action="store_true",
        default=argparse.SUPPRESS,
        help="跳过钥匙串密钥缓存，强制输入主密码",
    )
    group.add_argument(
        "--no-backup",
        action="store_true",
        default=argparse.SUPPRESS,
        help="本次写操作不做自动备份",
    )
    group.add_argument(
        "-q", "--quiet", action="store_true", default=argparse.SUPPRESS, help="只输出必要结果"
    )
    group.add_argument(
        "--password-stdin",
        action="store_true",
        default=argparse.SUPPRESS,
        help="从标准输入读主密码（脚本/管道场景）",
    )
    return parser


#: 自述行。裸跑 `pm` 和 `pm --help` 共用这一份，别再往 description 里抄第二遍。
BANNER = "本地优先加密保险库 · Argon2id 派生密钥 · AES-256-GCM 整体加密"


class _MainParser(argparse.ArgumentParser):
    """顶层解析器：让 `pm --help` 也带上自述行。

    裸跑 `pm` 时 `_print_overview` 会自己打印横幅，届时把 `show_banner` 关掉，
    免得同一行出现两次。子解析器不用这个类，`pm get --help` 保持干净。
    """

    show_banner = True

    def print_help(self, file: object = None) -> None:
        out = file or sys.stdout
        if self.show_banner:
            print(BANNER, file=out)
        super().print_help(file)


def build_parser() -> argparse.ArgumentParser:
    common = _common_options()
    parser = _MainParser(
        prog=PROG,
        epilog=f"首次使用：{PROG} init → {PROG} import <导出文件> → {PROG} web",
        parents=[common],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    parser.set_defaults(handler=None)
    subs = parser.add_subparsers(
        dest="command",
        metavar="<命令>",
        title="命令",
        parser_class=argparse.ArgumentParser,  # 子命令帮助不带自述行
    )

    def add(name: str, help_text: str, aliases: list[str] | None = None) -> argparse.ArgumentParser:
        return subs.add_parser(
            name,
            help=help_text,
            description=help_text,
            aliases=aliases or [],
            parents=[common],
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

    p = add("init", "创建新的加密保险库")
    p.add_argument("--force", action="store_true", help="已存在时覆盖（会销毁旧库）")
    p.add_argument("--no-keychain", action="store_true", help="不把密钥写入钥匙串缓存")
    p.set_defaults(handler=cmd_init)

    p = add("import", "导入 1PUX / CSV / JSON 导出文件")
    p.add_argument("file", help="导出文件路径（.1pux / .csv / .json）")
    p.add_argument("--overwrite", action="store_true", help="已存在同一条目时用新数据覆盖")
    p.add_argument("--no-archived", action="store_true", help="跳过归档条目")
    p.set_defaults(handler=cmd_import)

    p = add("ls", "列出条目")
    p.add_argument("--all", "-a", action="store_true", help="包含归档条目")
    p.add_argument("--cat", metavar="分类", help="按分类筛选（slug 或中文名，如 login、服务器）")
    p.add_argument("--tag", metavar="标签", help="按标签筛选")
    p.add_argument("--fav", action="store_true", help="只看收藏")
    p.add_argument(
        "--sort",
        choices=["smart", "title", "updated", "created", "category"],
        default="smart",
        help="排序（默认 smart：收藏优先、最近更新在前）",
    )
    p.add_argument("-n", "--limit", type=int, default=0, help="最多显示多少条（0=不限）")
    p.add_argument("--long", "-l", action="store_true", help="显示条目 id，便于后续命令引用")
    p.set_defaults(handler=cmd_ls)

    p = add("search", "模糊搜索标题 / 用户名 / 网址 / 标签 / 备注")
    p.add_argument("keyword", nargs="+", help="关键词，多个词之间是「或」")
    p.add_argument("--all", "-a", action="store_true", help="包含归档条目")
    p.add_argument("-n", "--limit", type=int, default=0, help="最多显示多少条")
    p.add_argument(
        "--long",
        "-l",
        action="store_true",
        help="附带收藏/归档状态（id 默认就显示，它可以直接喂给 get）",
    )
    p.set_defaults(handler=cmd_search)

    p = add("get", "查看单条明细（密码默认打码）")
    p.add_argument("key", help="标题 / 条目 id / id 前缀 / slug")
    p.add_argument(
        "index",
        nargs="?",
        type=int,
        metavar="序号",
        help="关键词命中多条时指定第几条（序号见候选列表，1 起）",
    )
    p.add_argument("--show", "-s", action="store_true", help="显示明文密码")
    p.add_argument("--copy", "-c", action="store_true", help="把密文复制到剪贴板")
    p.add_argument("--seconds", type=int, default=30, help="复制后多少秒清空剪贴板（0=不清空）")
    p.add_argument(
        "--field",
        metavar="标签",
        help="只输出该标签的字段值，给脚本用（如 VAR=$(pm get X --field 密码)）；"
        "标签命中多个时会报错，需写全",
    )
    p.add_argument("--form", action="store_true", help="附带浏览器抓取的网页表单字段")
    p.add_argument("--history", action="store_true", help="附带历史密码")
    p.set_defaults(handler=cmd_get)

    p = add("add", "新增条目（缺参数会交互式补全）")
    p.add_argument("--title", "-t", help="标题")
    p.add_argument("--cat", default=None, help="分类（默认 login，可用 pm categories 查看）")
    p.add_argument("--username", "-u", help="用户名")
    p.add_argument("--password", "-p", help="密码；留空则交互输入，配合 --generate 自动生成")
    p.add_argument("--generate", "-g", action="store_true", help="自动生成强密码")
    p.add_argument("--length", type=int, default=20, help="配合 --generate，默认 20 位")
    p.add_argument("--url", help="网址")
    p.add_argument("--notes", "-n", help="备注")
    p.add_argument("--tag", action="append", default=None, help="标签，可重复传")
    p.add_argument("--yes", "-y", action="store_true", help="不进入交互补全")
    p.set_defaults(handler=cmd_add)

    p = add("edit", "修改条目（只改显式传入的字段）")
    p.add_argument("key", help="标题 / 条目 id")
    p.add_argument("index", nargs="?", type=int, metavar="序号", help="命中多条时指定第几条")
    p.add_argument("--title", "-t", help="新标题")
    p.add_argument("--cat", help="新分类")
    p.add_argument("--username", "-u", help="新用户名")
    p.add_argument("--password", "-p", help="新密码")
    p.add_argument("--generate", "-g", action="store_true", help="生成新密码并写入")
    p.add_argument("--length", type=int, default=20, help="配合 --generate")
    p.add_argument("--url", help="新网址")
    p.add_argument("--notes", "-n", help="新备注")
    p.add_argument("--add-tag", action="append", default=None, help="追加标签")
    p.add_argument("--rm-tag", action="append", default=None, help="移除标签")
    p.add_argument("--favorite", action="store_true", help="标记收藏")
    p.add_argument("--unfavorite", action="store_true", help="取消收藏")
    p.add_argument("--archive", action="store_true", help="归档")
    p.add_argument("--unarchive", action="store_true", help="取消归档")
    p.set_defaults(handler=cmd_edit)

    p = add("rm", "删除条目")
    p.add_argument("key", help="标题 / 条目 id")
    p.add_argument("index", nargs="?", type=int, metavar="序号", help="命中多条时指定第几条")
    p.add_argument("--yes", "-y", action="store_true", help="跳过确认")
    p.set_defaults(handler=cmd_rm)

    p = add("copy", "把密文复制到剪贴板（pm get --copy 的快捷方式）")
    p.add_argument("key", help="标题 / 条目 id")
    p.add_argument("index", nargs="?", type=int, metavar="序号", help="命中多条时指定第几条")
    p.add_argument("--field", metavar="标签", help="复制指定标签的字段而不是主密码")
    p.add_argument("--seconds", type=int, default=30, help="多少秒后自动清空（0=不清空）")
    p.set_defaults(handler=cmd_copy)

    p = add("gen", "生成强密码")
    p.add_argument("--length", "-l", type=int, default=20, help="长度，默认 20")
    p.add_argument("--count", "-c", type=int, default=1, help="生成几个，默认 1")
    p.add_argument("--no-symbols", action="store_true", help="不含符号")
    p.add_argument("--no-digits", action="store_true", help="不含数字")
    p.add_argument("--no-upper", action="store_true", help="不含大写")
    p.add_argument("--no-lower", action="store_true", help="不含小写")
    p.add_argument("--avoid-ambiguous", action="store_true", help="排除易混字符 Il1O0o")
    p.set_defaults(handler=cmd_gen)

    p = add("audit", "安全体检：弱密码 / 重复使用 / 长期未更新")
    p.add_argument("--all", "-a", action="store_true", help="把归档条目也纳入体检")
    p.add_argument("--kind", choices=sorted(ISSUE_LABELS), help="只看某类问题")
    p.add_argument("-n", "--limit", type=int, default=0, help="每类最多列多少条（0=不限）")
    p.set_defaults(handler=cmd_audit)

    p = add("tags", "列出所有标签及数量")
    p.add_argument("--all", "-a", action="store_true", help="包含归档条目")
    p.set_defaults(handler=cmd_tags)

    p = add("categories", "列出支持的分类及当前条目数", aliases=["cats"])
    p.add_argument("--all", "-a", action="store_true", help="包含归档条目")
    p.set_defaults(handler=cmd_categories)

    p = add("stats", "保险库概况", aliases=["status"])
    p.set_defaults(handler=cmd_stats)

    p = add("export", "导出为 JSON")
    p.add_argument("target", help="输出文件路径")
    p.add_argument("--reveal", action="store_true", help="导出明文密码（默认打码）")
    p.set_defaults(handler=cmd_export)

    p = add("web", "启动本地 Web 界面（默认自动打开浏览器）")
    p.add_argument("--port", "-p", type=int, default=8848, help="端口，默认 8848")
    p.add_argument("--host", default="127.0.0.1", help="监听地址，默认仅本机")
    p.add_argument(
        "--open",
        dest="open_browser",
        action="store_true",
        default=True,
        help="启动后自动打开浏览器（默认行为）",
    )
    p.add_argument(
        "--no-open",
        dest="open_browser",
        action="store_false",
        help="不自动打开浏览器（脚本 / 远程 SSH 场景）",
    )
    p.add_argument("--idle", type=int, default=DEFAULT_IDLE_LOCK, help="空闲多少秒自动锁定，默认 600")
    p.add_argument("--debug", action="store_true", help="开启 Flask 调试模式")
    p.set_defaults(handler=cmd_web)

    p = add("passwd", "修改主密码", aliases=["rekey"])
    p.set_defaults(handler=cmd_passwd)

    p = add("lock", "清除钥匙串里的密钥缓存")
    p.set_defaults(handler=cmd_lock)

    p = add("backup", "把密文备份一份（默认 iCloud Drive）")
    p.add_argument("--to", metavar="DIR", help="备份目录，默认 iCloud Drive/pm-backup，可用 PM_BACKUP_DIR 指定")
    p.add_argument(
        "--keep",
        type=int,
        default=None,
        metavar="N",
        help=f"只保留最新 N 份，默认 {DEFAULT_KEEP}；0 表示不限",
    )
    p.add_argument("--list", "-l", action="store_true", help="只列出现有备份，不新建")
    p.set_defaults(handler=cmd_backup)

    return parser


# ── 解锁 ─────────────────────────────────────────────────────────────────────


def resolve_vault_path(args: argparse.Namespace) -> Path:
    explicit = getattr(args, "vault", None)
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("PM_VAULT")
    if env:
        return Path(env).expanduser()
    return default_vault_path()


def read_master_password(args: argparse.Namespace, prompt: str, *, confirm: bool = False) -> str:
    """取主密码：环境变量 PM_PASSWORD → stdin → 交互提示。"""
    env = os.environ.get("PM_PASSWORD")
    if env:
        return env
    hint = "需要主密码，但没有可用的输入来源。可用 PM_PASSWORD 环境变量或 --password-stdin。"
    piped = getattr(args, "password_stdin", False) or not sys.stdin.isatty()
    if piped:
        line = sys.stdin.readline().rstrip("\n")
        if line:
            return line
        if not sys.stdin.isatty():
            # stdin 被重定向且没内容：别再往 /dev/tty 弹提示——那跟调用者的重定向
            # 意图相反，且在无 tty 的环境里会直接卡死等输入。
            raise VaultError(hint)
    try:
        first = getpass.getpass(f"{prompt} ")
        if confirm:
            again = getpass.getpass("再输一次确认 ")
            if first != again:
                raise VaultError("两次输入不一致。")
        return first
    except EOFError as exc:
        raise VaultError(hint) from exc


def open_vault(args: argparse.Namespace) -> Vault:
    """打开并解锁保险库。"""
    path = resolve_vault_path(args)
    vault = Vault(path)
    if not vault.exists:
        raise VaultError(f"保险库不存在：{path}（先运行 `{PROG} init` 创建）")
    if not getattr(args, "no_cache", False) and vault.unlock_cached():
        return vault
    vault.unlock(
        read_master_password(args, "主密码:"), use_cache=not getattr(args, "no_cache", False)
    )
    if vault.last_cache_ok is False:
        # 钥匙串写入失败是静默的，用户只会觉得"怎么每次都要输密码"却无从排查
        print(
            STYLE.muted(
                "  ! 钥匙串密钥缓存写入失败，本次不会免密（钥匙串被锁或当前进程无权限）。"
            ),
            file=sys.stderr,
        )
    return vault


# ── 命令实现 ─────────────────────────────────────────────────────────────────


def cmd_init(args: argparse.Namespace, printer: Printer) -> int:
    path = resolve_vault_path(args)
    vault = Vault(path)
    if vault.exists and not args.force:
        printer.error(f"保险库已存在：{path}（覆盖请加 --force，会销毁现有数据）")
        return 1

    password = read_master_password(args, "设置主密码:", confirm=True)
    if len(password) < 8:
        printer.error("主密码至少 8 位 —— 它是唯一防线，没有找回通道。")
        return 1
    strength = evaluate(password)
    if strength.score <= 1:
        printer.warn(f"主密码强度为「{strength.label}」，建议换更长或更复杂的。")

    vault.create(password, meta={"source": "created", "host": os.uname().nodename}, force=args.force)
    cached = not args.no_keychain and keychain_available()
    if cached:
        vault.unlock(password, use_cache=True)
        cached = vault.last_cache_ok is True

    printer.data({"ok": True, "path": str(path), "keychain": cached})
    printer.text(
        f"{printer.style.ok('✓')} 保险库已创建：{path}",
        kv_block(
            [
                ("加密", "AES-256-GCM 整体加密 · Argon2id 派生密钥"),
                ("密钥缓存", "macOS 钥匙串，15 分钟" if cached else printer.style.muted("未启用")),
            ]
        ),
        "",
        printer.style.muted(f"  下一步：{PROG} import <1pux 文件>，然后 {PROG} web 打开界面"),
    )
    return 0


def cmd_import(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    source = Path(args.file).expanduser()
    if not printer.json:
        printer.text(printer.style.muted(f"读取 {source.name} …"))
    result = vault.import_file(
        source, overwrite=args.overwrite, include_archived=not args.no_archived
    )
    printer.data(
        {
            "file": str(source),
            "added": result.added,
            "updated": result.updated,
            "skipped": result.skipped,
            "total_in_vault": vault.count(),
        }
    )
    printer.blank()
    printer.text(
        f"{printer.style.ok('✓')} 导入完成：新增 {result.added} · 更新 {result.updated} · 跳过 {result.skipped}",
        printer.style.muted(f"  保险库现有 {vault.count()} 条"),
    )
    if result.skipped and not args.overwrite:
        printer.text(printer.style.muted("  重复条目已跳过（要覆盖请加 --overwrite）"))
    return 0


def _print_items(
    printer: Printer,
    items: list[Item],
    *,
    long: bool,
    total: int = 0,
    ids: bool = False,
) -> None:
    """列表视图。

    `ids` 与 `long` 分开：`ls` 是浏览（默认不显示 id，`--long` 才带），
    `search` 是定位——它的产物就是拿去喂 `pm get` 的句柄，所以 id 默认就在。
    """
    if not items:
        printer.text(printer.style.muted("（没有匹配的条目）"))
        return

    # 刻意不给标题加「标记槽」前缀：前缀只加在数据行、不加在表头，两边的内容
    # 起点就会差 2 列。状态改用独立列表达，同时避开了 ★ 这类宽度有歧义的字符
    # （East Asian Width = Ambiguous，CJK 字体下占 1 列还是 2 列取决于终端）。
    # 状态列只在「存在归档/收藏条目或有 --long」时出现，避免常见场景下一整列全是同一个值。
    show_state = long or any(i.archived or i.favorite for i in items)

    columns = [Column("标题", max_width=36), Column("分类", max_width=10)]
    if ids or long:
        columns.insert(0, Column("ID", max_width=8))
    columns += [Column("用户名", max_width=22), Column("网址", max_width=28)]
    if show_state:
        columns.append(Column("状态", max_width=12))
    columns += [Column("标签", max_width=16), Column("更新", max_width=10)]

    rows = []
    for item in items:
        row = [truncate(item.title, 36), item.category_name]
        if ids or long:
            row.insert(0, printer.style.muted(item.id[:8]))
        row += [
            truncate(item.username, 22) if item.username else printer.style.muted("—"),
            truncate(item.host, 28) if item.host else printer.style.muted("—"),
        ]
        if show_state:
            row.append(_state_cell(item, printer.style))
        row += [
            truncate(", ".join(item.tags), 16) if item.tags else printer.style.muted("—"),
            printer.style.muted(ts_to_date(item.updated_at) or "—"),
        ]
        rows.append(row)

    printer.text(render_table(columns, rows, style=printer.style))
    footer = f"共 {len(items)} 条"
    if total and total != len(items):
        footer += f"（筛选自 {total} 条）"
    printer.text(printer.style.muted(f"\n{footer}"))


def _state_cell(item: Item, style: Style) -> str:
    """状态列的单元格内容：归档 / 收藏 的组合。"""
    parts = []
    if item.archived:
        parts.append(style.muted("归档"))
    if item.favorite:
        parts.append(style.warn("收藏"))
    return "·".join(parts) if parts else style.ok("活跃")


def _print_candidates(printer: Printer, candidates: list[Item]) -> None:
    """候选一行一条，行首是序号。

    刻意**不复用列表视图**：`get` 缺的只是"是哪一条"，把 `search` 那张七列表
    再打一遍，用户等于重看了一遍搜索结果——分类、标签、更新时间对选哪条毫无帮助，
    反而让人以为 `get` 跑成了 `search`。这里只留序号 + 标题 + 一个能把同名条目
    分开的字段：用户名，没有就网址，再没有就分类。

    序号就是 `pm get <关键词> <序号>` 里那个数，省掉复制整串 uuid——这条命令的
    产物是给人看的，不是给机器拼的。
    """
    for position, item in enumerate(candidates, 1):
        who = item.username or item.host or item.category_name
        label = item.title or "（无标题）"
        if who:
            label = f"{label} · {who}"
        printer.text(f"  {printer.style.muted(position)}  {label}")


def _can_ask(printer: Printer) -> bool:
    """能不能就地问一句。

    stdin 和 stdout **都**得是终端。`pm get qq | pbcopy` 这类调用里 stdout 进了管道，
    在那儿画选项、等输入，既污染管道又把调用方卡死。--json 也一样：脚本要的是
    结构化结果，不是等人的光标。
    """
    if printer.json:
        return False
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _ask_pick(printer: Printer, key: str, candidates: list[Item]) -> Item | None:
    """交互式选一条。返回 None 表示取消。"""
    printer.error(f"“{key}” 命中 {len(candidates)} 条，选哪一条？")
    _print_candidates(printer, candidates)
    try:
        sys.stdout.flush()
        raw = input(f"\n  输入序号 [1-{len(candidates)}]，回车取消：").strip()
    except (EOFError, KeyboardInterrupt):
        printer.text("")
        return None
    if not raw:
        printer.text(printer.style.muted("  已取消。"))
        return None
    try:
        index = int(raw)
    except ValueError:
        printer.error(f"「{raw}」不是序号。")
        return None
    if not 1 <= index <= len(candidates):
        printer.error(f"序号 {index} 超出范围：命中 {len(candidates)} 条。")
        return None
    return candidates[index - 1]


def _resolve_or_pick(vault: Vault, args: argparse.Namespace, printer: Printer) -> Item | None:
    """解析关键词；命中多条时让用户按**序号**指定，而不是抄一整串 id。

    序号有三个来路，优先级从高到低：
      1. 命令里显式的第二个参数（`pm get qq 2`）——无状态，可写进脚本；
      2. 终端交互（stdin 是 TTY）——只敲一个数字；
      3. 都不是：打候选 + 用法提示，退出码非零。
    返回 None 表示没选成（提示已经输出）。
    """
    try:
        return vault.resolve(args.key)
    except AmbiguousItem as exc:
        candidates = sorted(exc.candidates, key=Item.sort_key)
        # JSON 是给脚本的出口：交互和序号都可能被误用，结构化的候选列表最稳
        printer.data({"error": str(exc), "candidates": [_item_brief(i) for i in candidates]})

        index = getattr(args, "index", None)
        if index is not None:
            if 1 <= index <= len(candidates):
                return candidates[index - 1]
            printer.error(f"序号 {index} 超出范围：命中 {len(candidates)} 条。")
            _print_candidates(printer, candidates)
            return None

        if _can_ask(printer):
            return _ask_pick(printer, args.key, candidates)

        printer.error(str(exc))
        _print_candidates(printer, candidates)
        printer.text(
            printer.style.muted(
                f"\n  用序号指定其中一条：{PROG} {args.command} {args.key} 2"
            )
        )
        return None


def cmd_ls(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    items = vault.filter(
        category=args.cat or "",
        tag=args.tag or "",
        include_archived=args.all,
        favorites_only=args.fav,
        sort=args.sort,
    )
    total = len(items)
    if args.limit > 0:
        items = items[: args.limit]
    printer.data(
        {"count": len(items), "total_matched": total, "items": [_item_brief(i) for i in items]}
    )
    _print_items(printer, items, long=args.long, total=total)
    return 0


def cmd_search(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    pool = vault.all_items(include_archived=args.all)
    matched: list[Item] = []
    seen: set[str] = set()
    for keyword in args.keyword:
        for item in pool:
            if item.id not in seen and item.matches(keyword):
                seen.add(item.id)
                matched.append(item)
    matched.sort(key=Item.sort_key)
    total = len(matched)
    if args.limit > 0:
        matched = matched[: args.limit]
    printer.data(
        {
            "keyword": args.keyword,
            "count": len(matched),
            "total_matched": total,
            "items": [_item_brief(i) for i in matched],
        }
    )
    _print_items(printer, matched, long=args.long, total=total, ids=True)
    return 0


def cmd_get(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    item = _resolve_or_pick(vault, args, printer)
    if item is None:
        return 1

    # --field / --copy 是给脚本用的窄通道：只吐值，不带装饰
    if args.field:
        value = _pick_field(item, args.field)
        if value is None:
            printer.error(f"条目「{item.title}」里没有匹配「{args.field}」的字段。")
            return 1
        if printer.json:
            printer.data({"title": item.title, "field": args.field, "value": value})
        else:
            print(value)
        return 0

    if args.copy:
        value = item.secret_value
        if not value:
            printer.error(f"条目「{item.title}」没有可复制的密文。")
            return 1
        return _do_copy(printer, item, value, item.secret_label, args.seconds)

    payload = _item_full(item, reveal=args.show, include_form=args.form)
    # JSON 是结构化导出，密码历史属于数据本身，不该被一个纯展示开关（--history）门控掉。
    # --history 只影响人看的文本视图。
    if not printer.json and not args.history:
        payload.pop("password_history", None)
    printer.data(payload)
    if printer.json:
        return 0

    printer.text(
        heading(item.title, style=printer.style),
        kv_block(
            [
                ("分类", f"{item.category_name}  {printer.style.muted(item.category)}"),
                ("条目 id", printer.style.muted(item.id)),
                ("保险库", item.vault or printer.style.muted("—")),
                ("状态", _status_text(item, printer.style)),
                (
                    "更新",
                    f"{ts_to_date(item.updated_at)}  {printer.style.muted(f'created {ts_to_date(item.created_at)}')}",
                ),
            ]
        ),
    )

    rows = []
    masked_any = False
    for label, value, secret in item.display_fields():
        if secret and not args.show:
            shown = printer.style.yellow(mask_secret(value))
            masked_any = True
        elif secret:
            shown = printer.style.ok(value)
        else:
            shown = value
        rows.append([label, shown])
    if rows:
        printer.text(
            heading("字段", style=printer.style),
            render_table([Column("", max_width=26), Column("值")], rows, style=printer.style),
        )

    if masked_any:
        # 打码却不告诉用户怎么解，等于把人卡在门口——他只能来问你一次。
        # 只列**日常要用的两个**：看一眼、复制走。`--field`（脚本取单值）属于少数场景，
        # 挤进这里只会稀释前两条的注意力——选项列得越全，越没人读得完。
        printer.text(
            printer.style.muted(
                f"\n  密文已打码。取它（{PROG} get <条目> 后面加其中一个）：\n"
                f"    --show   屏幕上看明文\n"
                f"    --copy   进剪贴板，30 秒后自动清空"
            )
        )

    if item.attachments:
        printer.text(heading("附件", style=printer.style))
        for attachment in item.attachments:
            if attachment.get("inline"):
                note = printer.style.muted("已内联加密存储")
            elif attachment.get("too_large"):
                note = printer.style.warn("超过 2 MB，仅记录元信息")
            else:
                note = printer.style.warn("导出包里没有对应文件")
            printer.text(
                f"  {attachment.get('name', '')}  {_size(attachment.get('size', 0))}  {note}"
            )

    if args.history and item.password_history:
        printer.text(heading(f"历史密码（{len(item.password_history)} 条）", style=printer.style))
        for entry in item.password_history[:12]:
            shown = entry["value"] if args.show else mask_secret(entry["value"])
            printer.text(f"  {ts_to_date(entry.get('time')) or '—':<12} {printer.style.muted(shown)}")

    if args.form and item.form_fields:
        printer.text(heading(f"网页表单详情（{len(item.form_fields)} 项）", style=printer.style))
        rows = [
            [label, value if (args.show or not secret) else mask_secret(value)]
            for label, value, secret in item.web_form_rows()
        ]
        printer.text(render_table([Column("", max_width=34), Column("值")], rows, style=printer.style))

    if item.secret_value:
        printer.text(
            heading("强度", style=printer.style),
            "  " + _strength_bar(_strength_payload(item.secret_value), printer.style),
        )
    return 0


def _pick_field(item: Item, wanted: str) -> str | None:
    """按标签取字段值。

    匹配规则：先精确（不分大小写），再唯一子串。**子串命中多条时报错并列出候选**，
    不取第一个——这跟 `pm get <标题>` 命中多条时的行为保持一致。取一个马上要粘到
    别处的密文，静默猜一个是最危险的失败方式。
    """
    needle = wanted.strip().lower()
    candidates: list[tuple[str, str]] = [
        ("用户名", item.username),
        ("密码", item.password),
        ("一次性密码", item.otp),
    ]
    for entry in item.urls:
        if entry.get("url"):
            candidates.append((entry.get("label") or "网址", entry["url"]))
    for field in item.fields:
        label = f"{field.section} · {field.title}" if field.section else field.title
        candidates.append((label, field.value))
    candidates.append(("备注", item.notes))

    for label, value in candidates:
        if label.lower() == needle and value:
            return value

    hits = [(label, value) for label, value in candidates if needle in label.lower() and value]
    if not hits:
        return None
    if len(hits) == 1:
        return hits[0][1]
    names = "、".join(label for label, _ in hits[:8])
    raise VaultError(
        f"「{item.title}」里有 {len(hits)} 个字段都匹配「{wanted}」，请写全标签：{names}"
    )


def _do_copy(printer: Printer, item: Item, value: str, label: str, seconds: int) -> int:
    if not clipboard_available():
        printer.error("当前环境没有 pbcopy，无法操作剪贴板。")
        return 1
    ok = copy_to_clipboard(value, clear_after=seconds)
    printer.data(
        {
            "ok": ok,
            "title": item.title,
            "field": label,
            "length": len(value),
            "clear_after": seconds,
        }
    )
    if not ok:
        printer.error("写入剪贴板失败。")
        return 1
    note = f"{seconds} 秒后自动清空" if seconds > 0 else printer.style.warn("不会自动清空")
    printer.text(
        f"{printer.style.ok('✓')} 已复制「{item.title}」的 {label}（{len(value)} 位）· {note}"
    )
    return 0


def cmd_add(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    interactive = not args.yes and sys.stdin.isatty()

    title = args.title
    if not title and interactive:
        title = input("标题: ").strip()
    if not title:
        printer.error("必须提供标题：用 --title，或去掉 -y 进入交互输入。")
        return 1

    username, password, url, notes = args.username, args.password, args.url, args.notes
    tags = list(args.tag or [])
    generate = args.generate

    if interactive:
        if username is None:
            username = input("用户名（可空）: ").strip()
        if password is None and not generate:
            choice = input("密码（回车=自动生成 / 输入 - =手动输入）: ").strip()
            if choice == "-":
                password = getpass.getpass("密码: ")
            elif choice:
                password = choice
            else:
                generate = True
        if url is None:
            url = input("网址（可空）: ").strip()
        if not tags:
            raw = input("标签（逗号分隔，可空）: ").strip()
            tags = [t.strip() for t in raw.replace("，", ",").split(",") if t.strip()]
        if notes is None:
            notes = input("备注（可空）: ").strip()

    if generate or not password:
        password = generate_password(args.length)
        if not printer.json:
            printer.text(printer.style.muted(f"已生成 {args.length} 位密码"))

    item = vault.create_item(
        title,
        category=args.cat or "login",
        username=username or "",
        password=password or "",
        url=url or "",
        notes=notes or "",
        tags=tags,
    )
    printer.data(_item_full(item, reveal=True))
    printer.text(
        f"{printer.style.ok('✓')} 已新增「{item.title}」",
        kv_block(
            [
                ("id", printer.style.muted(item.id[:8])),
                ("分类", item.category_name),
                ("密码", printer.style.ok(item.password) if item.password else printer.style.muted("—")),
            ]
        ),
    )
    return 0


def cmd_edit(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    item = _resolve_or_pick(vault, args, printer)
    if item is None:
        return 1

    patch: dict = {}
    for attr in ("title", "username", "url", "notes"):
        value = getattr(args, attr)
        if value is not None:
            patch[attr] = value
    if args.cat:
        patch["category"] = args.cat
    if args.password is not None:
        patch["password"] = args.password
    if args.generate:
        patch["password"] = generate_password(args.length)
        if not printer.json:
            printer.text(printer.style.muted(f"已生成 {args.length} 位新密码"))

    tags = list(item.tags)
    changed_tags = False
    for tag in args.add_tag or []:
        if tag not in tags:
            tags.append(tag)
            changed_tags = True
    for tag in args.rm_tag or []:
        if tag in tags:
            tags.remove(tag)
            changed_tags = True
    if changed_tags:
        patch["tags"] = tags

    if args.favorite:
        patch["favorite"] = True
    if args.unfavorite:
        patch["favorite"] = False
    if args.archive:
        patch["archived"] = True
    if args.unarchive:
        patch["archived"] = False

    if not patch:
        printer.error("没有指定要修改的字段，用 `pm edit --help` 查看可用选项。")
        return 1

    reveal = "password" in patch
    updated = vault.update(item.id, patch)
    printer.data(_item_full(updated, reveal=reveal))
    printer.blank()
    printer.text(
        f"{printer.style.ok('✓')} 已更新「{updated.title}」",
        kv_block([(key, _brief_value(value)) for key, value in patch.items()]),
    )


def _brief_value(value: object) -> str:
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, (list, tuple)):
        return "、".join(str(v) for v in value) or "（空）"
    if isinstance(value, str) and len(value) > 40:
        return value[:37] + "…"
    return str(value)


def cmd_rm(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    item = _resolve_or_pick(vault, args, printer)
    if item is None:
        return 1
    if not args.yes:
        if not sys.stdin.isatty():
            printer.error("非交互环境删除必须显式加 --yes。")
            return 1
        answer = input(f"确认删除「{item.title}」（{item.category_name}）？输入 yes 继续: ").strip()
        if answer.lower() not in ("y", "yes"):
            printer.text(printer.style.muted("已取消。"))
            return 0
    removed = vault.delete(item.id)
    printer.data({"ok": True, "deleted": _item_brief(removed), "total_in_vault": vault.count()})
    printer.text(f"{printer.style.ok('✓')} 已删除「{removed.title}」")
    return 0


def cmd_copy(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    item = _resolve_or_pick(vault, args, printer)
    if item is None:
        return 1
    if args.field:
        value = _pick_field(item, args.field)
        if value is None:
            printer.error(f"条目「{item.title}」里没有匹配「{args.field}」的字段。")
            return 1
        label = args.field
    else:
        value = item.secret_value
        label = item.secret_label
        if not value:
            printer.error(f"条目「{item.title}」没有可复制的密文。")
            return 1
    return _do_copy(printer, item, value, label, args.seconds)


def cmd_gen(args: argparse.Namespace, printer: Printer) -> int:
    passwords = [
        generate_password(
            args.length,
            symbols=not args.no_symbols,
            digits=not args.no_digits,
            upper=not args.no_upper,
            lower=not args.no_lower,
            avoid_ambiguous=args.avoid_ambiguous,
        )
        for _ in range(max(1, args.count))
    ]
    if printer.json:
        printer.data([{"password": pw, "strength": _strength_payload(pw)} for pw in passwords])
        return 0
    for password in passwords:
        printer.text(f"{password}   {_strength_bar(_strength_payload(password), printer.style)}")
    if len(passwords) == 1:
        printer.text(
            printer.style.muted(
                f"\n{args.length} 位 · 直接入库：{PROG} add -t 标题 -p '{passwords[0]}' -y"
            )
        )
    return 0


def _strength_bar(strength: dict | None, style: Style) -> str:
    if not strength:
        return style.muted("—")
    score = strength["score"]
    color = ["red", "red", "yellow", "green", "green"][score]
    bar = style("█" * (score + 1) + "░" * (4 - score), color)
    bits = f"{strength['bits']:.0f} bit"
    return f"{bar} {style.strong(strength['label'])}  {style.muted(bits)}"


def cmd_audit(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    report = audit(vault.all_items(include_archived=args.all))
    findings = (
        [f for f in report.findings if f.kind == args.kind] if args.kind else report.findings
    )

    printer.data(
        {
            "health": report.health,
            "total": report.total,
            "archived": report.archived,
            "with_password": report.with_password,
            "with_history": report.with_history,
            "score_histogram": report.score_histogram,
            "counts": {k: len(v) for k, v in report.by_kind.items()},
            "findings": [
                {
                    "kind": f.kind,
                    "label": f.label,
                    "title": f.title,
                    "item_id": f.item_id,
                    "detail": f.detail,
                }
                for f in findings
            ],
        }
    )
    if printer.json:
        return 0

    health = report.health
    color = "green" if health >= 70 else ("yellow" if health >= 40 else "red")
    rows = [
        ("健康分", printer.style(f"{health}/100", color, "bold")),
        ("条目", f"{report.total} 条（{report.archived} 条归档）"),
        ("含密码", f"{report.with_password} 条"),
        ("问题", f"{len(report.findings)} 项"),
    ]
    if report.with_history:
        rows.append(
            (
                "提示",
                printer.style.muted(
                    f"{report.with_history} 条携带 1Password 密码历史（正常特性，未计入问题）"
                ),
            )
        )
    printer.text(heading("安全体检", style=printer.style), kv_block(rows))

    printer.text(heading("强度分布", style=printer.style))
    labels = ["极弱", "弱", "一般", "强", "极强"]
    for index, count in enumerate(report.score_histogram):
        ratio = count / max(1, report.with_password)
        bar = "█" * int(ratio * 40)
        shade = "green" if index >= 3 else ("yellow" if index == 2 else "red")
        printer.text(f"  {labels[index]:<4}{count:>5}  {printer.style(bar, shade)}")

    grouped = report.by_kind
    if not grouped:
        printer.text(heading("没有发现明显问题", style=printer.style))
        return 0

    for kind, entries in grouped.items():
        if args.kind and kind != args.kind:
            continue
        printer.text(heading(f"{ISSUE_LABELS.get(kind, kind)}（{len(entries)}）", style=printer.style))
        shown = entries[: args.limit] if args.limit > 0 else entries
        rows = [[truncate(e.title, 30), truncate(e.detail, 52)] for e in shown]
        printer.text(
            render_table([Column("条目", max_width=30), Column("详情")], rows, style=printer.style)
        )
        if args.limit and len(entries) > args.limit:
            printer.text(printer.style.muted(f"  …另有 {len(entries) - args.limit} 条"))
    return 0


def cmd_tags(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    tags = vault.tags(include_archived=args.all)
    printer.data([{"tag": tag, "count": count} for tag, count in tags])
    if not tags:
        printer.text(printer.style.muted("（还没有任何标签）"))
        return 0
    printer.text(
        heading(f"标签（{len(tags)} 个）", style=printer.style),
        render_table(
            [Column("标签"), Column("数量", align="right")],
            [[tag, str(count)] for tag, count in tags],
            style=printer.style,
        ),
    )
    return 0


def cmd_categories(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    items = vault.all_items(include_archived=args.all)
    counts: dict[str, int] = {}
    for item in items:
        counts[item.category] = counts.get(item.category, 0) + 1

    printer.data(
        [
            {
                "uuid": spec.uuid,
                "slug": spec.slug,
                "name": spec.name_zh,
                "name_en": spec.name_en,
                "count": counts.get(spec.slug, 0),
                "verified": spec.verified,
            }
            for spec in all_categories()
        ]
    )
    if printer.json:
        return 0
    rows = [
        [
            spec.uuid,
            spec.slug,
            spec.name_zh,
            spec.name_en,
            str(counts.get(spec.slug, 0)),
            printer.style.muted("✓") if spec.verified else "",
        ]
        for spec in all_categories()
    ]
    printer.text(
        printer.style.muted("标记 ✓ 的分类已在真实 1PUX 导出中核对过字段模板\n"),
        render_table(
            [
                Column("UUID"),
                Column("slug"),
                Column("分类"),
                Column("英文"),
                Column("条目", align="right"),
                Column("核对"),
            ],
            rows,
            style=printer.style,
        ),
    )
    return 0


def cmd_stats(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    stats = vault.stats()
    printer.data(stats)
    if printer.json:
        return 0

    printer.text(
        heading(APP_TITLE, style=printer.style),
        kv_block(
            [
                ("文件", str(stats["path"])),
                ("大小", _size(stats["size_bytes"])),
                ("条目", f"{stats['items']} 条（{stats['active']} 活跃 / {stats['archived']} 归档）"),
                ("含密码", f"{stats['with_password']} 条"),
                ("收藏", f"{stats['favorites']} 条"),
                ("标签", f"{stats['tags']} 个"),
                ("创建", ts_to_date(stats["created_at"]) or "—"),
                (
                    "最后写入",
                    f"{ts_to_date(stats['updated_at'])}  {printer.style.muted(humanize(stats['updated_at']))}",
                ),
            ]
        ),
    )
    if stats["categories"]:
        printer.text(heading("分类分布", style=printer.style))
        width = max(len(name) for name in stats["categories"])
        for name, count in stats["categories"].items():
            printer.text(
                f"  {name:<{width}}  {count:>4}  {printer.style.cyan('▇' * min(count, 60))}"
            )
    source = stats.get("meta", {}).get("source_account")
    if source:
        printer.text(printer.style.muted(f"\n  数据来源：1Password 账号 {source}"))
    return 0


def cmd_export(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    target = Path(args.target).expanduser()
    path = vault.export_json(target, reveal=args.reveal)
    size = path.stat().st_size
    printer.data({"ok": True, "path": str(path), "bytes": size, "revealed": args.reveal})
    printer.text(
        f"{printer.style.ok('✓')} 已导出到 {path}（{_size(size)}）",
        printer.style.warn("  包含明文密码，用完记得删除！")
        if args.reveal
        else printer.style.muted("  密文字段已打码；需要明文请加 --reveal"),
    )
    return 0


def cmd_passwd(args: argparse.Namespace, printer: Printer) -> int:
    vault = open_vault(args)
    old = read_master_password(args, "当前主密码:")
    new = read_master_password(args, "新主密码:")
    if sys.stdin.isatty() and not getattr(args, "password_stdin", False):
        again = getpass.getpass("再输一次新密码 ")
        if new != again:
            printer.error("两次输入不一致。")
            return 1
    if len(new) < 8:
        printer.error("新主密码至少 8 位。")
        return 1
    try:
        vault.set_password(old, new)
    except WrongPassword:
        printer.error("当前主密码不正确。")
        return 1
    vault.unlock(new, use_cache=True)
    printer.data({"ok": True, "path": str(vault.path)})
    printer.text(f"{printer.style.ok('✓')} 主密码已更新，密钥缓存已刷新。")
    return 0


def cmd_lock(args: argparse.Namespace, printer: Printer) -> int:
    path = resolve_vault_path(args)
    Vault(path).clear_cached_key()
    printer.data({"ok": True, "path": str(path)})
    printer.text(f"{printer.style.ok('✓')} 已清除密钥缓存，下次操作需重新输入主密码。")
    return 0


def cmd_backup(args: argparse.Namespace, printer: Printer) -> int:
    """手动备份。刻意不打开保险库——备份搬的是密文，不需要主密码。"""
    path = resolve_vault_path(args)
    directory = Path(args.to).expanduser() if args.to else backup_mod.default_backup_dir()

    if args.list:
        return _list_backups(printer, directory)

    result = backup_mod.backup_once(path, target_dir=directory, keep=args.keep)
    if not result.ok:
        printer.error(f"备份失败：{result.error}")
        printer.text(
            printer.style.muted(
                f"  目标目录：{result.dir}"
                f"\n  可用 --to <目录> 换一个位置，或用 PM_BACKUP_DIR 固定在环境变量里。"
            )
        )
        return 1

    printer.data(result.to_dict())
    where = f"{result.label}（{result.dir}）" if result.label != str(result.dir) else str(result.dir)
    printer.text(
        f"{printer.style.ok('✓')} 已备份 → {result.filename}",
        kv_block(
            [
                ("位置", where),
                ("大小", _size(result.bytes)),
                ("校验", printer.style.muted(f"sha256 {result.digest[:16]}…")),
                ("份数", f"保留 {result.kept} 份" + (f"，本次清理 {result.removed} 份" if result.removed else "")),
            ]
        ),
        "",
        printer.style.muted(f"  恢复：cp <上面那个文件> {path}"),
    )
    return 0


def _list_backups(printer: Printer, directory: Path) -> int:
    files = backup_mod.existing_backups(directory)
    label = backup_mod.dir_label(directory)
    printer.data(
        {
            "dir": str(directory),
            "label": label,
            "count": len(files),
            "backups": [
                {
                    "file": str(p),
                    "filename": p.name,
                    "bytes": p.stat().st_size,
                    "mtime": p.stat().st_mtime,
                }
                for p in reversed(files)
            ],
        }
    )
    if not files:
        printer.text(
            f"{printer.style.muted('○')} 还没有备份：{directory}",
            printer.style.muted(f"  跑一次 `{PROG} backup`，或任意写操作都会自动备份。"),
        )
        return 0
    total = sum(p.stat().st_size for p in files)
    printer.text(
        heading(f"{label} 的备份（{len(files)} 份 · {_size(total)}）"),
        render_table(
            [Column("时间"), Column("文件"), Column("大小", align="right")],
            [
                [
                    _mtime_text(p),
                    p.name,
                    _size(p.stat().st_size),
                ]
                for p in reversed(files)
            ],
            style=printer.style,
        ),
        "",
        printer.style.muted(f"  {directory}"),
    )
    return 0


def _mtime_text(path: Path) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(path.stat().st_mtime))


def _emit_backup_notice(printer: Printer) -> None:
    """写操作之后的自动备份提示。每次命令至多一行。

    JSON 模式必须让 stdout 保持"一个对象"，所以提示走 stderr —— 结构化消费者读
    stdout，人在终端上两种都能看见。
    """
    result = backup_mod.take_notice()
    if result is None:
        return
    line = ("✓ " if result.ok else "! ") + result.hint()
    if printer.json:
        print(line, file=sys.stderr)
        return
    if printer.quiet:
        return
    sys.stdout.flush()  # 管道里 stdout 是块缓冲的，不刷会把提示挤到正常输出前面
    print(f"{printer.style.ok('✓') if result.ok else printer.style.warn('!')} {result.hint()}")


def port_is_free(host: str, port: int) -> bool:
    """端口能不能绑。绑不上说明已被占用，提前报错比等 Flask 抛栈好看得多。"""
    import socket

    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((probe_host, port))
        except OSError:
            return False
    return True


def open_browser_when_ready(url: str, host: str, port: int, on_result=None) -> None:
    """等端口真的开始 accept 之后再开浏览器。

    不能用一个固定 sleep 盲开：Flask 是在 `app.run()` 里才绑端口的，sleep 太短会
    打开一个连不上的页面，太长又显得迟钝。这里改成轮询端口，连上即开，最多等 10 秒。
    """
    import socket
    import threading
    import webbrowser

    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host

    def worker() -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.25)
                if sock.connect_ex((probe_host, port)) == 0:
                    try:
                        ok = webbrowser.open(url)
                    except Exception:
                        ok = False
                    if on_result:
                        on_result(bool(ok))
                    return
            time.sleep(0.15)
        if on_result:
            on_result(False)

    threading.Thread(target=worker, daemon=True, name="pm-open-browser").start()


def _install_stop_handler() -> None:
    """把 SIGTERM 转成可捕获的 SystemExit，让 `kill <pid>` 也能走到统一收尾。

    Ctrl-C（SIGINT）不需要额外处理——但要注意 werkzeug 内部会把它吞掉，
    所以"已停止"的提示只能放在 finally 里，放在 except KeyboardInterrupt 里永远不会执行。
    """
    import signal

    def handler(_signum, _frame):
        raise SystemExit(0)

    try:
        signal.signal(signal.SIGTERM, handler)
    except (ValueError, OSError):
        pass  # 非主线程或平台不支持，忽略即可


def cmd_web(args: argparse.Namespace, printer: Printer) -> int:
    try:
        from .webapp import create_app
    except ImportError as exc:  # pragma: no cover
        printer.error(f"Web 模式需要 Flask：{exc}")
        return 1

    path = resolve_vault_path(args)
    if not Vault(path).exists:
        printer.error(f"保险库不存在：{path}（先运行 `{PROG} init`）")
        return 1

    if not port_is_free(args.host, args.port):
        printer.error(f"端口 {args.port} 已被占用。换一个：{PROG} web -p {args.port + 1}")
        printer.text(
            printer.style.muted(f"  查看占用者：lsof -nP -iTCP:{args.port} -sTCP:LISTEN")
        )
        return 1

    app = create_app(vault_path=str(path), idle_lock=args.idle)
    url = f"http://{args.host}:{args.port}/"
    printer.data(
        {
            "ok": True,
            "url": url,
            "vault": str(path),
            "idle_lock": args.idle,
            "open_browser": args.open_browser,
            "pid": os.getpid(),
        }
    )
    if not printer.json:
        hint = (
            "正在等待服务就绪，随后自动打开浏览器"
            if args.open_browser
            else f"未自动打开浏览器，请手动访问 {url}"
        )
        print(
            f"\n  {printer.style.head(APP_TITLE)}  {printer.style.muted('Web 模式')}\n"
            f"  {printer.style.ok('→')} {printer.style.strong(url)}\n"
            f"  {printer.style.muted(f'保险库 {path}')}\n"
            f"  {printer.style.muted(f'空闲 {args.idle // 60} 分钟自动锁定')}\n"
            f"  {printer.style.muted(f'退出：在本终端按 Ctrl-C，或在别处 kill {os.getpid()}')}\n"
            f"  {printer.style.muted(hint)}\n"
        )

    if args.open_browser:
        def report(ok: bool) -> None:
            message = (
                printer.style.ok("✓ 已在浏览器中打开")
                if ok
                else printer.style.warn("! 没能自动打开浏览器，请手动访问上面的地址")
            )
            print(f"  {message}", flush=True)

        open_browser_when_ready(url, args.host, args.port, on_result=report)

    _install_stop_handler()
    try:
        app.run(host=args.host, port=args.port, debug=args.debug, threaded=True, use_reloader=False)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        # werkzeug 会自己吞掉 SIGINT，所以收尾提示必须挂在 finally 上
        if not printer.json:
            print(printer.style.muted(f"\n已停止，端口 {args.port} 已释放。"))
    return 0


def _status_text(item: Item, style: Style) -> str:
    parts = [style.warn("归档") if item.archived else style.ok("活跃")]
    if item.favorite:
        parts.append(style.warn("★ 收藏"))
    return "  ".join(parts)


def _size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / 1024 / 1024:.2f} MB"


# ── 入口 ─────────────────────────────────────────────────────────────────────


def _print_overview(parser: _MainParser) -> None:
    """裸跑 `pm` 时给一个带状态的自述，而不是干巴巴地甩 help。"""
    path = default_vault_path()
    vault = Vault(path)
    print(f"{STYLE.head(APP_TITLE)} {STYLE.muted(__version__)}")
    print(BANNER)
    print()
    if vault.exists:
        size = _size(path.stat().st_size)
        if vault.unlock_cached():
            stats = vault.stats()
            summary = (
                f"{size} · {stats['items']} 条 · "
                f"活跃 {stats['active']} / 归档 {stats['archived']}"
            )
            print(f"  {STYLE.ok('●')} {path}  {STYLE.muted(summary)}")
            vault.lock()
        else:
            print(f"  {STYLE.warn('●')} {path}  {STYLE.muted(f'{size} · 已锁定')}")
    else:
        print(f"  {STYLE.muted('○')} 还没有保险库  {STYLE.muted(str(path))}")
        print(f"    {STYLE.ok(f'先运行 {PROG} init')}")
    _print_backup_status()
    print()
    parser.show_banner = False  # 上面已经打印过了
    parser.print_help()


def _print_backup_status() -> None:
    """自述里带一行备份状态 —— 备份目录可能是别人指过去的，得让人看得见。"""
    directory = backup_mod.default_backup_dir()
    files = backup_mod.existing_backups(directory)
    tail = f"  {STYLE.muted(f'{len(files)} 份')}"
    print(f"  {STYLE.muted('↳')} 备份 {backup_mod.dir_label(directory)}" + tail)


def main(argv: list[str] | None = None) -> int:
    global STYLE
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    STYLE = Style(enabled=False if getattr(args, "no_color", False) else None)
    import password_manager.ui as ui_module

    ui_module.STYLE = STYLE
    printer = Printer(
        as_json=getattr(args, "json", False),
        quiet=getattr(args, "quiet", False),
        style=STYLE,
    )

    backup_mod.set_enabled(not getattr(args, "no_backup", False))
    backup_mod.clear_notice()

    handler = getattr(args, "handler", None)
    if handler is None:
        _print_overview(parser)
        return 0

    try:
        code = handler(args, printer)
    except WrongPassword as exc:
        printer.error(str(exc))
        printer.text(STYLE.muted(f"  连续失败可用 `{PROG} lock` 清除密钥缓存后重试。"))
        return 1
    except AmbiguousItem as exc:
        # 兜底：走 _resolve_or_pick 的命令不会落到这儿（它们就地让用户选了）
        printer.error(str(exc))
        _print_candidates(printer, sorted(exc.candidates, key=Item.sort_key))
        return 1
    except (ItemNotFound, VaultError) as exc:
        printer.error(str(exc))
        return 1
    except KeyboardInterrupt:
        printer.text(STYLE.muted("\n已取消。"))
        return 130
    # 写在命令之后：提示的是这次命令触发的备份，不是命令本身的结果
    _emit_backup_notice(printer)
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
