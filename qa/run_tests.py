#!/usr/bin/env python3
"""pm 回归测试 —— 自建临时保险库，跑完 CLI 与 Web 两套断言后自行清理。

用法：
    uv run python qa/run_tests.py            # 全部
    uv run python qa/run_tests.py --cli      # 只跑 CLI
    uv run python qa/run_tests.py --web      # 只跑 Web

刻意不依赖 pytest：这套断言的价值在于"用真实 1PUX 跑一遍真实落盘 + 真实 HTTP"，
引入测试框架只会增加一层间接。断言失败会以非零码退出。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#: 测试用的 1PUX 导出包。**路径不写死**：那是本机的个人文件，写进代码等于把
#: 账号标识和目录结构跟着仓库一起公开。用 --pux 或 PM_QA_PUX 指定。
DEFAULT_PUX = os.environ.get("PM_QA_PUX", "")
MASTER = "QaTest!2026"

GREEN = "\033[32m"
RED = "\033[31m"
DIM = "\033[90m"
RESET = "\033[0m"

results = {"pass": 0, "fail": 0}


def check(label: str, condition: bool, extra: str = "") -> bool:
    if condition:
        results["pass"] += 1
        print(f"  {GREEN}✓{RESET} {label} {DIM}{extra}{RESET}")
    else:
        results["fail"] += 1
        print(f"  {RED}✗{RESET} {label} {RED}{extra}{RESET}")
    return bool(condition)


def section(title: str) -> None:
    print(f"\n{DIM}── {title} ──{RESET}")


# ── CLI ──────────────────────────────────────────────────────────────────────


def _env(home: str, password: str = MASTER) -> dict:
    """测试一律用 PM_VAULT 指向临时保险库。

    不靠 PM_HOME 的推导——测试要盯的是"这个库"，而不是"默认路径推导得对不对"。
    `PYTHONPATH` 指向 `src/`，让被测进程跑**当前源码**而不是 `.venv` 里那份
    `uv sync --no-editable` 拷进去的副本；否则改完源码忘记 sync，测试会对着旧代码
    全绿（这个坑真踩过）。
    """
    return {
        **os.environ,
        "PM_HOME": home,
        "PM_VAULT": os.path.join(home, "vault.pmv"),
        "PM_PASSWORD": password,
        # 备份目录必须钉在临时目录里：默认值是 iCloud Drive，不钉就会往用户真盘里灌
        # 上百个测试副本（而且是在他不知情的情况下）。
        "PM_BACKUP_DIR": os.path.join(home, "backup"),
        "PYTHONPATH": os.path.join(REPO, "src"),
        "NO_COLOR": "1",
    }


def pm(args: list[str], home: str, password: str = MASTER) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "password_manager.cli", *args],
        capture_output=True,
        text=True,
        env=_env(home, password),
        cwd=REPO,
        # 显式断掉 stdin：`get` 命中多条时会在终端里问序号，继承测试进程的 stdin
        # 会让它挂在提示上。这里钉住"管道里不追问"的场景。
        stdin=subprocess.DEVNULL,
    )


def pm_json(args: list[str], home: str, password: str = MASTER):
    proc = pm([*args, "--json"], home, password)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"    {RED}非 JSON 输出{RESET}: {proc.stdout[:160]} / {proc.stderr[:160]}")
        return None


def run_path_tests() -> None:
    """默认路径必须只由环境决定，与「在哪个目录调用」无关。

    曾经存在一条"在源码仓库里就用仓库的 data/vault.pmv"的分支，于是同一个命令在
    仓库内敲和在别处敲解析到两个不同的库——`uv run pm import <导出文件>` 能静默
    造出第二个真库。断言锁住修好之后的不变量。
    """
    section("默认路径与调用方式无关")
    code = "from password_manager.vault import default_vault_path; print(default_vault_path())"
    env = {k: v for k, v in os.environ.items() if k not in ("PM_HOME", "PM_VAULT")}
    env["PYTHONPATH"] = os.path.join(REPO, "src")
    env["NO_COLOR"] = "1"

    seen: dict[str, str] = {}
    for label, cwd in (("仓库内", REPO), ("/tmp", "/tmp"), ("家目录", os.path.expanduser("~"))):
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, env=env, cwd=cwd
        )
        seen[label] = proc.stdout.strip() or f"<失败: {proc.stderr.strip()[:60]}>"

    check(
        "三种 cwd 解析到同一个库",
        len(set(seen.values())) == 1,
        f"-> {seen}",
    )
    check(
        "默认落在 ~/.pm/vault.pmv",
        set(seen.values()) == {os.path.join(os.path.expanduser("~"), ".pm", "vault.pmv")},
        f"-> {sorted(set(seen.values()))}",
    )
    check(
        "仓库 data/ 下不会冒出保险库",
        not os.path.exists(os.path.join(REPO, "data", "vault.pmv")),
    )
    check(
        "PM_HOME 仍能压过默认值",
        subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, cwd=REPO,
            env={**env, "PM_HOME": os.path.join(REPO, "data", "probe")},
        ).stdout.strip() == os.path.join(REPO, "data", "probe", "vault.pmv"),
    )


def run_banner_tests() -> None:
    """自述行只能有一处来源，且只打印一遍。

    曾经同一句文案同时躺在 `description` 和裸跑横幅里，敲一下 `pm` 就看见两遍
    意思重复的话。断言锁住：裸跑 `pm` 与 `pm --help` 各一遍，子命令帮助不带。
    """
    section("自述行只说一遍")
    env = {k: v for k, v in os.environ.items() if k not in ("PM_HOME", "PM_VAULT")}
    env["PYTHONPATH"] = os.path.join(REPO, "src")
    env["NO_COLOR"] = "1"

    def probe(code: str, env_override: dict | None = None) -> str:
        return subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, cwd=REPO,
            env=env_override or env,
        ).stdout

    banner = probe("from password_manager.cli import BANNER; print(BANNER, end='')").strip()
    check("自述行有出处", bool(banner), "-> 空字符串")

    def hits(args_src: str) -> int:
        return probe(f"from password_manager.cli import main; main({args_src})").count(banner)

    check("裸跑 pm 只出现一遍", hits("[]") == 1)
    check("pm --help 只出现一遍", hits("['--help']") == 1)
    check("子命令帮助不带自述行", hits("['get', '--help']") == 0)

    # 用假 TTY 逼出配色，才能验证"这句没被灰化"——管道里配色本来就关了。
    # NO_COLOR 必须摘掉：它优先级高于 isatty，留着就永远测不到配色分支。
    color_env = {k: v for k, v in env.items() if k != "NO_COLOR"}
    colored = probe(
        "import io, sys\n"
        "from password_manager.cli import main\n"
        "class _T(io.StringIO):\n"
        "    def isatty(self): return True\n"
        "buf = _T()\n"
        "sys.stdout = buf\n"
        "try:\n"
        "    main([])\n"
        "except SystemExit:\n"
        "    pass\n"
        "sys.stdout = sys.__stdout__\n"
        "print(buf.getvalue())",
        color_env,
    )
    check("假 TTY 下确实上色了", "\x1b[90m" in colored, "-> 没检测到配色，下面两条断言失去意义")
    check(
        "自述行不被灰化",
        f"\x1b[2m{banner}" not in colored and f"\x1b[90m{banner}" not in colored,
        "-> 仍带 dim/gray 转义",
    )
    check(
        "自述行在状态行上方",
        colored.find(banner) < colored.find("vault.pmv"),
        "-> 顺序被打乱了",
    )


def run_backup_tests() -> None:
    """自动备份：写操作触发、副本可信、轮转、可关、失败不阻断写。

    自带临时 home —— 这一节要反复增删条目，混进 CLI 那节的计数断言会互相干扰。
    """
    section("自动备份")
    home = tempfile.mkdtemp(prefix="pm-bak-")
    bdir = os.path.join(home, "backup")

    def backups() -> list[str]:
        if not os.path.isdir(bdir):
            return []
        return sorted(
            f for f in os.listdir(bdir) if f.startswith("pm-") and f.endswith(".pmv")
        )

    def digest(path: str) -> str:
        return hashlib.sha256(open(path, "rb").read()).hexdigest()

    def add(title: str, *extra: str) -> subprocess.CompletedProcess:
        return pm(["add", "-t", title, "-p", "Str0ng!Pass#2026x", "-y", *extra], home)

    try:
        pm(["init", "--no-keychain"], home)
        check("建库本身不产生备份（空库没什么好留的）", backups() == [], f"-> {backups()}")

        proc = add("备份甲")
        check("写操作成功", proc.returncode == 0, proc.stderr.strip()[:70])
        files = backups()
        check("写一次自动备份一份", len(files) == 1, f"-> {files}")
        check("提示行出现在 stdout", "已自动备份" in proc.stdout, f"-> {proc.stdout[-80:]!r}")
        check("提示行带文件名", bool(files) and files[0] in proc.stdout)

        source = os.path.join(home, "vault.pmv")
        copy = os.path.join(bdir, files[0]) if files else ""
        check("副本与源逐字节一致", bool(copy) and digest(source) == digest(copy))
        check("副本权限 0600", bool(copy) and (os.stat(copy).st_mode & 0o777) == 0o600)
        check(
            "文件名带时间戳",
            bool(files) and len(files[0]) == len("pm-YYYYMMDD-HHMMSS.pmv"),
            f"-> {files[0] if files else ''}",
        )

        add("备份乙")
        check("写两次两份（同一秒也不覆盖）", len(backups()) == 2, f"-> {backups()}")

        # --json 下 stdout 必须还是"一个对象"，提示只能走 stderr
        proc = add("备份丙", "--json")
        parsed = None
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            pass
        check(
            "--json 时 stdout 仍是单个 JSON",
            isinstance(parsed, dict) and parsed.get("title") == "备份丙",
            f"-> {proc.stdout[:70]!r}",
        )
        check("--json 时提示走 stderr", "已自动备份" in proc.stderr)

        before = len(backups())
        proc = add("免备份", "--no-backup")
        check("--no-backup 抑制备份", proc.returncode == 0 and len(backups()) == before)
        subprocess.run(
            [sys.executable, "-m", "password_manager.cli", "add", "-t", "免备份二",
             "-p", "x", "-y"],
            env={**_env(home), "PM_NO_BACKUP": "1"}, cwd=REPO, capture_output=True, text=True,
        )
        check("PM_NO_BACKUP=1 抑制备份", len(backups()) == before)

        # 备份失败不能影响已经写好的保险库
        blocker = os.path.join(home, "blocker")
        with open(blocker, "w") as handle:
            handle.write("不是目录")
        proc = subprocess.run(
            [sys.executable, "-m", "password_manager.cli", "add", "-t", "备份失败",
             "-p", "x", "-y"],
            env={**_env(home), "PM_BACKUP_DIR": blocker}, cwd=REPO,
            capture_output=True, text=True,
        )
        check("备份失败不阻断写操作", proc.returncode == 0, proc.stderr.strip()[:70])
        check(
            "失败提示如实报出",
            "自动备份失败" in proc.stdout + proc.stderr,
            f"-> {(proc.stdout + proc.stderr)[-80:]!r}",
        )
        check("保险库确实写进去了", pm_json(["get", "备份失败"], home) is not None)

        # 轮转只碰自己写的文件
        note = os.path.join(bdir, "readme.txt")
        with open(note, "w") as handle:
            handle.write("手工放进来的文件")
        for index in range(4):
            add(f"轮转{index}")
        proc = pm(["backup", "--keep", "2"], home)
        check("轮转后只剩 2 份", len(backups()) == 2, f"-> {len(backups())}")
        check("轮转报告清理了几份", "清理" in proc.stdout, f"-> {proc.stdout[-80:]!r}")
        check("轮转不碰非备份文件", os.path.exists(note))

        proc = pm(["backup", "--list"], home)
        check("--list 列出现有备份", ".pmv" in proc.stdout and "2 份" in proc.stdout)

        # 备份路径不碰密钥：不给密码、不给钥匙串，也必须能跑通
        env = {k: v for k, v in _env(home).items() if k != "PM_PASSWORD"}
        proc = subprocess.run(
            [sys.executable, "-m", "password_manager.cli", "backup", "--no-cache"],
            env=env, cwd=REPO, capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        check(
            "pm backup 不需要主密码",
            proc.returncode == 0 and "已备份" in proc.stdout,
            f"-> {(proc.stdout + proc.stderr)[-80:]!r}",
        )

        # 默认目录：优先 iCloud Drive，退化到 ~/.pm/backup
        probe_env = {
            k: v for k, v in os.environ.items()
            if k not in ("PM_BACKUP_DIR", "PM_HOME", "PM_VAULT")
        }
        probe_env["PYTHONPATH"] = os.path.join(REPO, "src")
        out = subprocess.run(
            [sys.executable, "-c",
             "from password_manager.backup import default_backup_dir; print(default_backup_dir())"],
            capture_output=True, text=True, env=probe_env, cwd=REPO,
        ).stdout.strip()
        icloud = os.path.join(os.path.expanduser("~"),
                              "Library", "Mobile Documents", "com~apple~CloudDocs", "pm-backup")
        check(
            "默认备份目录落位正确",
            out in (icloud, os.path.expanduser("~/.pm/backup")),
            f"-> {out}",
        )
    finally:
        shutil.rmtree(home, ignore_errors=True)


def run_cli_tests(home: str, pux: str) -> None:
    section("建库与导入")
    proc = pm(["init", "--no-keychain"], home)
    check("pm init 成功", proc.returncode == 0, proc.stderr.strip()[:60])
    check("落盘权限 0600", (os.stat(f"{home}/vault.pmv").st_mode & 0o777) == 0o600)

    # 另建一个库，走带钥匙串缓存的路径。这里不假设缓存一定成功——在沙箱里
    # `security add-generic-password` 会被挡掉。要点是：无论成败都不能崩，
    # 而且必须如实报告结果（曾经是静默失败，用户只会觉得"怎么每次都要输密码"）。
    cache_home = os.path.join(home, "cachecase")
    os.makedirs(cache_home, exist_ok=True)
    proc = pm(["init"], cache_home, password="CacheCase!2026")
    check("pm init 带钥匙串路径不崩", proc.returncode == 0, proc.stderr.strip()[:60])
    check(
        "pm init 如实报告密钥缓存状态",
        "密钥缓存" in proc.stdout and ("15 分钟" in proc.stdout or "未启用" in proc.stdout),
        f"-> {[l.strip() for l in proc.stdout.splitlines() if '密钥缓存' in l]}",
    )

    r = pm_json(["import", pux], home)
    check("首次导入 241 条", r and r["added"] == 241, f"-> {r}")
    r = pm_json(["import", pux], home)
    check("重复导入幂等（全部跳过）", r and r["added"] == 0 and r["skipped"] == 241, f"-> {r}")

    section("密文不可读")
    blob = open(f"{home}/vault.pmv", "rb").read()
    # 明文从库里现取，不把任何真实密码抄进代码——测试代码会跟着仓库一起被公开。
    real_pwd = pm_json(["get", "Aliyun", "--show"], home)["password"]
    check("取到用于比对的明文", bool(real_pwd) and "•" not in real_pwd, f"-> {len(real_pwd)} 位")
    for keyword, label in (
        (real_pwd.encode(), "条目主密码"),
        (b"aliyun", "服务名"),
        (b"password", "通用词"),
    ):
        check(f"密文中搜索不到{label}", keyword not in blob, f"-> {len(blob)} bytes 已扫描")
    check("文件头为 PMVAULT 魔数", blob[:8] == b"PMVAULT\x00")

    section("查询")
    r = pm_json(["ls", "--cat", "无线路由器", "--all"], home)
    check("按中文分类筛选", r and r["count"] == 2, f"-> {[i['title'] for i in r['items']] if r else None}")
    r = pm_json(["ls", "--cat", "wireless_router", "--all"], home)
    check("按 slug 筛选结果一致", r and r["count"] == 2)
    r = pm_json(["search", "wifi", "--all"], home)
    check("模糊搜索命中", r and r["count"] >= 3, f"-> {r['count'] if r else None}")
    check("搜索默认排除归档", pm_json(["search", "wifi"], home)["count"] < r["count"])

    # search 的产物就是喂给 get 的句柄。表里不给 id，用户只能去看 --help 猜 --long；
    # 而 `get` 命中多条时又只给一串十六进制 id——两边对不上，等于把"选哪条"甩回给人。
    r = pm_json(["search", "git"], home)
    proc = pm(["search", "git"], home)
    check("搜索结果首列是 id", proc.stdout.splitlines()[0].startswith("ID"),
          f"-> {proc.stdout.splitlines()[0][:30]}")
    check(
        "表里的 id 能直接喂 get",
        bool(r and r["items"]) and pm(["get", r["items"][0]["id"][:8]], home).returncode == 0,
        f"-> {r['items'][0]['id'][:8] if r and r['items'] else '—'}",
    )

    # 候选条数必须和 search 数出来的一致：resolve 曾把归档条目也算进候选，
    # 于是 `get` 说 3 条、`search` 只列 2 条，第三条既看不见也没法判断该不该选。
    active = pm_json(["search", "git"], home)["count"]
    proc = pm(["get", "git"], home)
    check("歧义候选数与 search 一致", f"命中 {active} 条" in proc.stderr,
          f"-> {proc.stderr.strip()[:44]} / search={active}")
    cand = [line for line in proc.stdout.splitlines() if re.match(r"^\s+\d+\s{2}\S", line)]
    check("歧义时逐条列出候选（序号在行首）", len(cand) == active,
          f"-> {len(cand)} 行 / search={active}")
    # 一整张七列表重打一遍等于让用户重看搜索结果，`get` 就退化成了 `search`。
    # 失败信息不打印候选内容：里面是真实账号，跑挂了贴日志就等于把账号贴出去。
    check("候选不复用列表视图，只留区分字段",
          bool(cand) and all("·" in line for line in cand) and "分类" not in proc.stdout,
          f"-> {len(cand)} 行，含「·」{all('·' in line for line in cand) if cand else False}")
    check("非终端下提示用序号指定", f"pm get git 2" in proc.stdout,
          f"-> {proc.stdout.strip().splitlines()[-1][:44] if proc.stdout else '—'}")

    # 序号：`pm get <关键词> <n>` 无状态、无隐式上下文，可以写进脚本/历史记录。
    # 序号的顺序必须和 search 列表一致，否则用户对着上面那张表数出来的号是错的。
    titles = [i["title"] for i in pm_json(["search", "git"], home)["items"]]
    proc = pm(["get", "git", "2"], home)
    check("第二个参数按序号取第 2 条",
          proc.returncode == 0 and titles[1] in proc.stdout,
          f"-> rc={proc.returncode}")
    proc = pm(["get", "git", "9"], home)
    check("序号越界时报错不猜", proc.returncode != 0 and "超出范围" in proc.stderr,
          f"-> {proc.stderr.strip()[:40]}")

    # 终端里直接问一句：只敲一个数字，连序号都不用带去第二条命令。
    # 真 TTY 造不出来，就把 stdin / stdout 都换成 isatty 恒真的 StringIO——
    # 这同时证明了判断只看 isatty，不看别的东西。
    interactive = subprocess.run(
        [sys.executable, "-c",
         "import io, sys\n"
         "from password_manager.cli import main\n"
         "class _TTY(io.StringIO):\n"
         "    def isatty(self): return True\n"
         "sys.stdin = _TTY('1\\n')\n"
         "out = _TTY()\n"
         "sys.stdout = out\n"
         "try:\n"
         "    main(['get', 'git'])\n"
         "except SystemExit:\n"
         "    pass\n"
         "sys.stdout = sys.__stdout__\n"
         "print(out.getvalue())\n"],
        capture_output=True, text=True, env=_env(home), cwd=REPO,
        stdin=subprocess.DEVNULL,
    )
    check("终端里可交互选序号",
          "1  " in interactive.stdout and titles[0] in interactive.stdout,
          f"-> rc={interactive.returncode}，序号行={'1  ' in interactive.stdout}")

    check("管道里不追问（避免卡死脚本）",
          "选哪一条" not in pm(["get", "git"], home).stdout,
          "-> 非 TTY 时必须直接失败退出")

    section("生成与写入")
    proc = pm(["gen", "-l", "32", "--avoid-ambiguous"], home)
    pwd = proc.stdout.split()[0]
    check("gen 生成 32 位", len(pwd) == 32, f"-> {len(pwd)}")
    check("gen 排除易混字符", not any(c in pwd for c in "Il1O0o"))

    proc = pm(["add", "-t", "QA条目", "-u", "qa", "-p", "Str0ng!Pass#2026x", "-y"], home)
    check("add 非交互新增", proc.returncode == 0, proc.stderr.strip()[:60])
    proc = pm(["edit", "QA条目", "--add-tag", "qa标签", "--favorite"], home)
    check("edit 追加标签与收藏", "qa标签" in proc.stdout)
    proc = pm(["edit", "QA条目", "--generate", "--length", "28"], home)
    check("edit --generate 换密码", "已更新" in proc.stdout)
    d = pm_json(["get", "QA条目", "--show"], home)
    check("新密码进入历史", len(d["password_history"]) >= 1, f"-> {len(d['password_history'])} 条")
    check("历史保留旧密码", any("Str0ng!Pass#2026x" == h["value"] for h in d["password_history"]))
    proc = pm(["rm", "QA条目", "--yes"], home)
    check("rm 删除", "已删除" in proc.stdout)
    check("删除后条目数回落", pm_json(["stats"], home)["items"] == 241)

    section("打码与定位")
    d = pm_json(["get", "Aliyun"], home)
    secret_rows = [r for r in d["rows"] if r["secret"]]
    check("get 打码态有密文行", len(secret_rows) >= 1)
    check("打码态不泄露明文", "•" in secret_rows[0]["value"], f"-> {secret_rows[0]['value']!r}")
    check("顶层 password 也打码", "•" in d["password"])
    check("打码态仍给强度", bool((d.get("strength") or {}).get("label")), f"-> {d['strength']['label']}")

    d = pm_json(["get", "Aliyun", "--show"], home)
    check("--show 给出明文", all("•" not in r["value"] for r in d["rows"] if r["secret"]))

    # 打码却不告诉用户怎么解，等于把人卡在门口——只能来问一次。
    # 只列日常要用的两个（看一眼 / 复制走）。--field 属于脚本场景，挤进来会稀释注意力。
    plain = pm(["get", "Aliyun"], home)
    check(
        "打码时给出两个日常取法",
        "密文已打码" in plain.stdout and "--show" in plain.stdout and "--copy" in plain.stdout,
        "-> 应给出 看明文 / 进剪贴板 两条",
    )
    check(
        "提示保持精简，不塞脚本用的开关",
        "--field" not in plain.stdout,
        "-> 选项越全越没人读得完；--field 写在 --help 里",
    )
    check("提示里写明剪贴板会自动清空", "自动清空" in plain.stdout)
    shown = pm(["get", "Aliyun", "--show"], home)
    check("--show 后不再啰嗦", "密文已打码" not in shown.stdout)
    # 提示里的两条必须真的能跑
    check(
        "--copy 与 pm copy 等价",
        "已复制" in pm(["get", "Aliyun", "--copy", "--seconds", "0"], home).stdout
        and "已复制" in pm(["copy", "Aliyun", "--seconds", "0"], home).stdout,
    )

    # --field 是唯一能把「裸值」取进 shell 变量的路径，但标签含糊时必须报错——
    # 静默取第一个命中，等于让用户把错的密文粘到别处去。
    # 标签歧义那几条需要一条带多个密文字段的条目，改用合成数据在 run_field_tests 里测。
    check(
        "--field 精确标签可用",
        pm(["get", "Aliyun", "--field", "密码"], home).stdout.strip() == real_pwd,
    )
    check("--field 无命中时报错", pm(["get", "Aliyun", "--field", "不存在zzz"], home).returncode != 0)

    proc = pm(["get", "git"], home)
    check("歧义关键词被拒并提示", proc.returncode != 0 and "命中" in proc.stderr, f"-> {proc.stderr.strip()[:60]}")
    proc = pm(["get", "不存在的条目zzz"], home)
    check("找不到条目报错", proc.returncode != 0)

    section("密码校验")
    proc = pm(["stats", "--no-cache"], home, password="DefinitelyWrong!999")
    check("错误主密码被拒", proc.returncode != 0, f"-> rc={proc.returncode}")
    check("错误提示可读", "主密码" in proc.stderr, f"-> {proc.stderr.strip()[:50]}")
    check("正确主密码通过", pm(["stats", "--no-cache"], home).returncode == 0)

    pm(["lock"], home)
    check("pm lock 后错误密码立即被拒",
          pm(["stats"], home, password="DefinitelyWrong!999").returncode != 0)

    section("审计")
    a = pm_json(["audit", "--all"], home)
    check("体检覆盖 241 条", a["total"] == 241, f"-> {a['total']}")
    check("健康分是整数", isinstance(a["health"], int), f"-> {a['health']}/100")
    check("问题分类齐全", {"weak", "reused", "stale", "empty"} <= set(a["counts"]), f"-> {a['counts']}")
    check("历史密码单列、不计入问题", a["with_history"] > 0 and "old" not in a["counts"],
          f"-> with_history={a['with_history']}")
    check("弱密码结论无「长度充足」噪音",
          not any("长度充足" in f["detail"] for f in a["findings"]))

    section("导入导出")
    pm(["export", f"{home}/masked.json"], home)
    pm(["export", f"{home}/plain.json", "--reveal"], home)
    masked = open(f"{home}/masked.json", encoding="utf-8").read()
    plain = open(f"{home}/plain.json", encoding="utf-8").read()
    check("打码导出不含明文", real_pwd not in masked)
    check("--reveal 导出含明文", real_pwd in plain)
    check("导出文件权限 0600", (os.stat(f"{home}/plain.json").st_mode & 0o777) == 0o600)

    r = pm_json(["import", f"{home}/plain.json"], home)
    check("回读自身导出不产生重复", r and r["added"] == 0, f"-> {r}")

    section("剪贴板安全阀")
    proc = pm(["copy", "Aliyun", "--seconds", "2"], home)
    check("copy 成功", proc.returncode == 0, proc.stdout.strip()[:44])
    clip = subprocess.run(["pbpaste"], capture_output=True, text=True).stdout
    # 失败时只报长度：把剪贴板内容打进控制台，等于把密码写进 CI 日志。
    check("写入剪贴板", clip.strip() == real_pwd, f"-> 长度 {len(clip.strip())}")
    time.sleep(4)
    clip = subprocess.run(["pbpaste"], capture_output=True, text=True).stdout
    check("超时后自动清空剪贴板", clip.strip() == "", f"-> 长度 {len(clip.strip())}")


# ── 合成数据：字段标签 ───────────────────────────────────────────────────────

#: 合成的假凭据。**测试代码里的每个凭据都必须是假的**——它会被一起推上远端。
FAKE_OPERATOR = "qa-operator-pw"
FAKE_ADMIN = "qa-admin-pw"


def run_field_tests() -> None:
    """--field 的标签解析，对着自建的合成条目测。

    这几条断言需要「一条目里带多个密文字段」，而 `pm add` 造不出自定义字段，
    只能往库里塞。塞的是假数据：把真实条目的密码/标签写进断言，等于让它们
    跟着仓库公开。
    """
    section("字段标签（合成数据）")
    home = tempfile.mkdtemp(prefix="pm-field-")
    try:
        pm(["init", "--no-keychain"], home)
        seed = (
            "import os\n"
            "from password_manager.models import Field\n"
            "from password_manager.vault import Vault\n"
            "vault = Vault(os.environ['PM_VAULT'])\n"
            "vault.unlock(os.environ['PM_PASSWORD'], use_cache=False)\n"
            "vault.create_item(\n"
            "    'QA 路由器', category='wireless_router', username='qa-user',\n"
            "    fields=[\n"
            "        Field(title='运营商密码', value=os.environ['FAKE_OPERATOR'], secret=True),\n"
            "        Field(title='管理密码', value=os.environ['FAKE_ADMIN'], secret=True),\n"
            "    ],\n"
            ")\n"
            "vault.create_item(\n"
            "    'QA 登录', category='login',\n"
            "    username='qa@example.com', password='qa-login-pw',\n"
            ")\n"
        )
        env = {**_env(home), "FAKE_OPERATOR": FAKE_OPERATOR, "FAKE_ADMIN": FAKE_ADMIN}
        subprocess.run([sys.executable, "-c", seed], env=env, cwd=REPO, capture_output=True,
                       stdin=subprocess.DEVNULL, check=True)

        proc = pm(["get", "QA 路由器", "--field", "管理密码"], home)
        check("--field 按标签取值", proc.stdout.strip() == FAKE_ADMIN, f"-> rc={proc.returncode}")

        ambiguous = pm(["get", "QA 路由器", "--field", "密码"], home)
        check(
            "--field 标签有歧义时报错并列出候选",
            ambiguous.returncode != 0 and "都匹配" in ambiguous.stderr,
            f"-> rc={ambiguous.returncode} {ambiguous.stderr.strip()[:70]}",
        )
        check(
            "--field 写全标签即通过",
            pm(["get", "QA 路由器", "--field", "运营商密码"], home).stdout.strip() == FAKE_OPERATOR
            and pm(["get", "QA 路由器", "--field", "管理密码"], home).stdout.strip() == FAKE_ADMIN,
        )

        d = pm_json(["get", "QA 路由器"], home)
        check("非 Login 保留用户字段标签", d["secret_label"] == "运营商密码",
              f"-> {d['secret_label']}")
        check("密文字段不被改名成「密码」",
              "运营商密码" in [r["label"] for r in d["rows"] if r["masked"]])
        check("打码态不含明文", all(FAKE_OPERATOR not in r["value"] for r in d["rows"]))
    finally:
        subprocess.run(
            [sys.executable, "-m", "password_manager.cli", "lock"],
            env=_env(home), cwd=REPO, capture_output=True,
        )
        shutil.rmtree(home, ignore_errors=True)


# ── Web ──────────────────────────────────────────────────────────────────────


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class WebClient:
    """裸 urllib 客户端，显式禁用代理——沙箱环境里的本机请求会被代理吞掉。"""

    def __init__(self, base: str):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def __call__(self, method, path, body=None, token=None, origin=None):
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if token:
            headers["X-PM-Token"] = token
        if origin:
            headers["Origin"] = origin
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=15) as resp:
                return resp.status, json.loads(resp.read()), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw), dict(exc.headers)
            except Exception:
                return exc.code, {"raw": raw[:120]}, dict(exc.headers)

    def html(self, path: str) -> str:
        """取原始 HTML —— 有些断言只能靠看源码（比如"没有在 JS 里改布局"）。"""
        req = urllib.request.Request(self.base + path)
        try:
            with self.opener.open(req, timeout=15) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.read().decode("utf-8", "replace")


def run_web_tests(home: str) -> None:
    port = free_port()
    server = subprocess.Popen(
        # --no-open 是必须的：pm web 默认会自动打开浏览器，跑测试时不能弹窗
        [sys.executable, "-m", "password_manager.cli",
         "web", "-p", str(port), "--idle", "600", "--no-open"],
        env=_env(home),
        cwd=REPO,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        client = WebClient(base)
        for _ in range(50):
            try:
                client("GET", "/api/status")
                break
            except Exception:
                time.sleep(0.2)
        else:
            check("Web 服务启动", False, "连接超时")
            return
        check("Web 服务启动", True, base)

        section("解锁页布局")
        page = client.html("/")
        check("解锁页能取到", "<form" in page, f"-> {len(page)} bytes")
        # 「用缓存解锁」那一行必须由服务端渲染。曾经是加载后由 JS 插进去的，
        # 卡片因此多出一行、垂直居中重算，视觉上就是「先居中，再往上蹿 32px」。
        check(
            "缓存行交给服务端渲染，加载后不改布局",
            "cacheRow.style.display" not in page,
            "JS 在加载后插入/显示元素会让居中卡片重新居中",
        )
        # place-items:center 在卡片比视口高时会把顶部推到负偏移，而滚动原点在 0，
        # 于是主密码框被裁掉且滚不到。flex + margin:auto 是它的安全版本。
        check(
            "居中用的是安全方案（flex + margin:auto）",
            "margin: auto" in page and "place-items: center" not in page,
            "place-items:center 在溢出时会把顶部裁掉且无法滚动到",
        )

        section("鉴权")
        check("未解锁拒绝访问", client("GET", "/api/items")[0] == 401)
        check("错误密码 401", client("POST", "/api/unlock", {"password": "nope"})[0] == 401)
        status, body, _ = client("POST", "/api/unlock", {"password": MASTER, "cache": False})
        check("解锁成功", status == 200, f"-> {status}")
        token = body["token"]
        check("解锁返回 token", len(token) > 20)
        check("统计正确", body["items"] == 241, f"-> {body['items']} 条")
        check("无 token 被拒", client("GET", "/api/items")[0] == 401)
        check("伪造 token 被拒", client("GET", "/api/items", token="bogus")[0] == 401)
        check("跨站 Origin 被拒",
              client("GET", "/api/items", token=token, origin="http://evil.example")[0] == 403)
        check("同源 Origin 放行",
              client("GET", "/api/items", token=token, origin=base)[0] == 200)

        section("读取与脱敏")
        status, listing, headers = client("GET", "/api/items?archived=1", token=token)
        check("列表 241 条", listing["count"] == 241, f"-> {listing['count']}")
        check("列表项不含密文字段",
              not any(k in listing["items"][0] for k in ("password", "otp")),
              f"-> {sorted(listing['items'][0])[:5]}…")
        check("响应带 no-store", "no-store" in headers.get("Cache-Control", ""))
        check("响应带 X-Frame-Options", headers.get("X-Frame-Options") == "DENY")

        item_id = listing["items"][0]["id"]
        _, masked, _ = client("GET", f"/api/items/{item_id}", token=token)
        check("reveal=0 密文为空串",
              all(f["value"] == "" for f in masked["fields"] if f["secret"]))
        check("reveal=0 仍给强度", bool((masked.get("strength") or {}).get("label")))
        check("reveal=0 历史密码为空", sum(1 for h in masked["history"] if h["value"]) == 0)
        _, shown, _ = client("GET", f"/api/items/{item_id}?reveal=1", token=token)
        check("reveal=1 给出明文",
              any(f["value"] for f in shown["fields"] if f["secret"]))

        section("增删改")
        status, created, _ = client(
            "POST", "/api/items",
            {"title": "QA-Web", "category": "server", "username": "root",
             "password": "Str0ng!Pass#2026x", "url": "https://qa.invalid"},
            token=token,
        )
        check("新增返回 201", status == 201, f"-> {status}")
        new_id = created["item"]["id"]
        check("分类映射正确", created["item"]["category_name"] == "服务器")
        _, after, _ = client("PATCH", f"/api/items/{new_id}",
                             {"notes": "改过", "favorite": True}, token=token)
        check("PATCH 生效", after["item"]["notes"] == "改过" and after["item"]["favorite"])
        # 备份提示走响应体而不是轮询：前端只在一个地方弹 toast
        note = after.get("backup") or {}
        check("写操作响应带回备份结果", note.get("ok") is True, f"-> {note}")
        check("备份结果带目录标签与份数", bool(note.get("label")) and note.get("kept", 0) >= 1)
        _, gen, _ = client("PATCH", f"/api/items/{new_id}", {"generate": True, "length": 28}, token=token)
        check("generate 生成 28 位", bool(gen.get("generated")) and len(gen["generated"]) == 28)
        _, hist, _ = client("GET", f"/api/items/{new_id}?reveal=1", token=token)
        check("旧密码进入历史", any(h["value"] == "Str0ng!Pass#2026x" for h in hist["history"]))
        check("空 PATCH 被拒", client("PATCH", f"/api/items/{new_id}", {}, token=token)[0] == 400)
        check("空标题被拒", client("POST", "/api/items", {"title": ""}, token=token)[0] == 400)

        section("生成器与元信息")
        _, g, _ = client("POST", "/api/gen", {"length": 32, "avoid_ambiguous": True}, token=token)
        pw = g["passwords"][0]["value"]
        check("生成 32 位", len(pw) == 32, f"-> {len(pw)}")
        check("排除易混字符", not any(c in pw for c in "Il1O0o"))
        _, meta, _ = client("GET", "/api/meta?archived=1", token=token)
        check("meta 返回 22 个分类", len(meta["categories"]) == 22, f"-> {len(meta['categories'])}")
        _, aud, _ = client("GET", "/api/audit", token=token)
        check("体检返回健康分", isinstance(aud["health"], int), f"-> {aud['health']}/100")
        check("体检把历史密码单列",
              aud["with_history"] > 0 and all(f["kind"] != "old" for f in aud["findings"]))

        section("删除与锁定")
        check("删除成功", client("DELETE", f"/api/items/{new_id}", token=token)[0] == 200)
        check("删除后 404", client("GET", f"/api/items/{new_id}", token=token)[0] == 404)
        check("条目数回落", client("GET", "/api/status", token=token)[1]["items"] == 241)
        check("锁定成功", client("POST", "/api/lock", token=token)[0] == 200)
        check("旧 token 失效", client("GET", "/api/items", token=token)[0] == 401)
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


# ── 入口 ─────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description="pm 回归测试")
    parser.add_argument(
        "--pux", default=DEFAULT_PUX, help="用于测试的 1PUX 文件（也可用 PM_QA_PUX 指定）"
    )
    parser.add_argument("--cli", action="store_true", help="只跑 CLI 断言")
    parser.add_argument("--web", action="store_true", help="只跑 Web 断言")
    parser.add_argument("--keep", action="store_true", help="保留临时目录便于排查")
    args = parser.parse_args()

    if not args.pux or not os.path.exists(args.pux):
        print(f"{RED}找不到测试用的 1PUX：{args.pux or '（未指定）'}{RESET}")
        print("用 --pux 指定一个 .1pux 文件，或 export PM_QA_PUX=<路径>。")
        return 2

    only_cli = args.cli and not args.web
    only_web = args.web and not args.cli

    home = tempfile.mkdtemp(prefix="pm-qa-")
    print(f"{DIM}临时保险库目录：{home}{RESET}")
    try:
        if only_web:
            # 只跑 Web 断言时需要先把数据灌好；跑 CLI 断言时由它自己走 init + import
            subprocess.run(
                [sys.executable, "-m", "password_manager.cli", "init", "--no-keychain"],
                env=_env(home), cwd=REPO, capture_output=True,
            )
            subprocess.run(
                [sys.executable, "-m", "password_manager.cli", "import", args.pux],
                env=_env(home), cwd=REPO, capture_output=True,
            )
        if not only_web:
            run_path_tests()
            run_banner_tests()
            run_backup_tests()
            run_cli_tests(home, args.pux)
            run_field_tests()
        if not only_cli:
            run_web_tests(home)
    finally:
        subprocess.run(
            [sys.executable, "-m", "password_manager.cli", "lock"],
            env=_env(home), cwd=REPO, capture_output=True,
        )
        if not args.keep:
            shutil.rmtree(home, ignore_errors=True)

    total = results["pass"] + results["fail"]
    color = GREEN if results["fail"] == 0 else RED
    print(f"\n{color}通过 {results['pass']} / {total}{RESET}"
          + (f"  {RED}失败 {results['fail']}{RESET}" if results["fail"] else ""))
    return 1 if results["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
