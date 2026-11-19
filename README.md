# password-manager

本地优先的加密密码保险库。一个命令 `pm`，两种用法：命令行直接查改，或起一个本地
Web 界面做完整的增删改查。数据从 1Password 的 `.1pux` 导出包导入。

## 快速开始

```bash
uv tool install --force .
pm init                                    # 设置主密码
pm import ~/archive/1PasswordExport-xxx.1pux
pm web --open                              # 打开本地界面
```

不带 `--open` 就不自动开浏览器；服务固定监听 `http://127.0.0.1:8848/`。

## 安全模型

| 事项 | 做法 |
|---|---|
| 密钥派生 | Argon2id，64 MiB / 3 轮 / 4 通道，每库独立随机盐 |
| 落盘加密 | AES-256-GCM **整体加密**。磁盘上不存在明文、明文索引或可枚举结构 |
| 完整性 | 密文的认证标签同时承担「主密码是否正确」的校验，不另存校验和 |
| 写盘 | 每次写入都先备份成 `.bak`，再经临时文件 + `os.replace()` 原子换名 |
| 异地备份 | 写成功后复制一份密文到备份目录（默认 iCloud Drive），副本不改变威胁模型：同上表，磁盘上没有明文 |
| 文件权限 | 保险库与导出文件一律 `0600` |
| 解锁缓存 | macOS 钥匙串，默认 15 分钟失效；缓存的是**派生密钥**而非主密码 |
| Web 监听 | 只绑 `127.0.0.1`；读接口也要 CSRF token；空闲自动清掉内存中的密钥 |

密钥派生参数写在保险库文件头里，所以日后调整默认参数不会让旧库打不开。

**没有的东西**：主密码找回、密码提示、云同步（备份是单向副本，不是同步）、浏览器插件、
局域网访问开关。主密码丢了就是永久丢数据——请定期 `pm export` 备份。

## 命令

```
pm init                                  创建保险库
pm import <文件> [--overwrite]            导入 1pux / csv / json
pm ls [-a] [--cat 分类] [--tag 标签] [-n N] [--long]
pm search <关键词>... [-a] [-n N] [--long]  模糊搜索，结果自带 id 可直喂 get
pm get <标题|id> [序号] [--show] [--copy] [--field 标签] [--form] [--history]
pm add [-t 标题] [-u 用户名] [-p 密码|--generate] [--url] [-n 备注] [--tag] [-y]
pm edit <标题|id> [序号] [...]             只改显式传入的字段
pm rm <标题|id> [序号] [--yes]
pm copy <标题|id> [序号] [--field 标签] [--seconds 30]
pm gen [-l 20] [-c 1] [--avoid-ambiguous]
pm audit [-a] [--kind weak] [--limit N]   弱密码 / 重复使用 / 长期未更新
pm tags | pm categories | pm stats
pm export <输出.json> [--reveal]
pm web [-p 8848] [--no-open] [--idle 600]
pm backup [--to 目录] [--keep 30] [--list]
pm passwd | pm lock
```

定位条目时依次尝试：完整 id → 完整标题 → 唯一 id 前缀 → slug 化标题 → 唯一子串命中。
同一层里活跃条目优先于归档条目（归档只在「这层只命中归档」时才用，按完整 id 始终可取）。
命中多条时**按序号选**，不猜也不会让人抄 32 位 uuid：

```
$ pm get qq
✗ “qq” 命中 2 条，选哪一条？
  1  QQ · 1234567890
  2  QQ · 2345678901

  输入序号 [1-2]，回车取消：
```

终端里它就地追问，敲个 1 就完事；不想被追问就一次说完：`pm get qq 2`。
序号顺序与 `pm search` 的列表顺序一致。stdout 或 stdin 不是终端（管道、脚本、`--json`）
时不会追问，而是打印候选并以非零码退出——绝不在管道里等人。
`search` 默认不列归档条目，`get` 的候选同样不列——两边的条数应当一致。

所有命令都支持 `--json`，便于脚本消费：

```bash
pm get github --field 密码            # 只吐值，直接喂给别的命令
pm ls --json | jq '.items[].title'
pm search wifi --json | jq -r '.items[].id' | xargs -I{} pm get {} --copy
```

主密码来源优先级：`--password-stdin` → `PM_PASSWORD` 环境变量 → 非 TTY 时读 stdin
→ 交互提示。`PM_VAULT` 可指定保险库路径替代 `--vault`。

`pm get --json` 里有两个来源不同的列表：`fields` 是模型原始的自定义字段
（普通 Login 这里是空的，因为用户名/密码在顶层 `username`/`password` 上），
`rows` 是人看到的合成展示行。脚本想要"跟人看到的一样"就读 `rows`。

## Web 界面

```bash
pm web              # 默认监听 127.0.0.1:8848，并自动打开浏览器
pm web --no-open    # 不自动开（脚本 / 远程 SSH 场景）
pm web -p 8849      # 换端口
```

**退出**：在跑它的那个终端按 `Ctrl-C`，或另开一个终端 `kill <PID>`。PID 直接印在启动
横幅上，不用自己找。两种方式都会打印 `已停止，端口 xxxx 已释放。` 并以退出码 0 结束。

注意 `Ctrl-C` 的收尾提示挂在 `finally` 上是有原因的：werkzeug 内部会自己吞掉
`KeyboardInterrupt`，写 `except KeyboardInterrupt:` 的分支永远不会执行，表现就是
"能退出但一言不发"。

**服务停了，页面会自己清空。** 这是个真实的信息泄露面：进程一死，内存里的密钥就没了，
但浏览器标签页上**仍然显示着刚才渲染出来的密码字段**——页面不会因为后端死掉而自己消失，
而且重新输入地址时浏览器还会先拿上次的缓存画面顶一下。所以前端每 5 秒 ping 一次
`/api/status`（该接口不需要 CSRF token），连不上就把整页替换成停止提示；标签页切回前台时
也立即补一次探测。这样"人离开工位时屏幕上还摆着明文"这条就没有了。

**解锁页的两个细节。**

「用缓存解锁」那一行由服务端按真实缓存状态决定是否渲染——不能交给 JS 在加载后插入：
卡片一旦多出一行，垂直居中就要重算，视觉上就是「先居中、再往上蹿 32px」。顺带修掉一个
逻辑错：原判断是 `keychain_available()`（平台是 macOS），所以没有缓存时也会显示这个按钮，
点下去必然失败。

居中用的是 `flex` + 子元素 `margin: auto`，不是 `place-items: center`。后者在卡片比视口高
时会把顶部推到负偏移，而**滚动原点在 0，溢出到上方的部分永远滚不到**——主密码框会被直接
裁掉。`margin: auto` 是同一件事的安全版本：空间不够时自动边距退化成 0，卡片从内边距开始
排布，整页正常可滚。

**钥匙串缓存写不进去会明确告诉你。** 缓存写入失败原本是完全静默的（用户只会觉得"怎么每次
都让我输密码"），现在 CLI 与 `pm init` 都会如实报告结果。

服务没在跑也没关系——磁盘上始终只有密文。

浏览器不是用一个固定 sleep 盲开的——那样 Flask 还没绑端口就会打开一个连不上的页面。
实际做法是轮询端口，连上即开（最多等 10 秒），并把打开结果如实回报。端口被占用时
直接报错并给出换端口的建议，不会先弹一个死页面。

单页应用，纯 Jinja + 原生 JS，没有前端构建链。功能：搜索 / 分类与标签筛选 /
归档与收藏开关 / 详情抽屉 / 新增与编辑 / 密码生成器 / 安全体检 / 导入导出 /
逐字段复制（复制后 30 秒自动清空剪贴板）/ 空闲自动锁定倒计时。

明文只在 `/api/items/<id>?reveal=1` 时出内存，且响应带 `Cache-Control: no-store`。
列表接口永远不含密文字段。

## 从 1Password 迁移

`pm import` 优先选 `.1pux`。同账号导出的 `.csv` 只有 228 行且全部塌缩成 Login
（丢掉 Document / Bank Account / Server / Wireless Router 等分类和自定义字段），
只当兜底用。

导入按 1Password 自己的 `item.uuid` 去重，同一份文件重复导入只会更新不会翻倍
（实测：首导新增 241，再导跳过 241）。

会完整保留的东西：分类、自定义字段（含中文标题）、标签、备注、归档状态、收藏、
密码历史、附件（2 MB 内内联加密存储）、以及浏览器扩展抓取的网页表单字段。

字段标题**原样保留**，不按字段 id 反查官方英文名——导出包里用户可能已经改成
「管理密码」这类自定义标题，任何 id→英文名映射都会覆盖掉它。

## 数据存放

| 指定方式 | 路径 |
|---|---|
| `--vault /x/y.pmv` | `/x/y.pmv`（优先级最高） |
| `PM_VAULT=/x/y.pmv` | `/x/y.pmv` |
| `PM_HOME=/x` | `/x/vault.pmv` |
| 都没给 | `~/.pm/vault.pmv` |

**默认路径与「在哪个目录调用」无关** —— 在仓库里 `uv run pm` 和在别处 `pm` 指向同一个库。
（早期版本有一条"在源码仓库里就用仓库的 `data/vault.pmv`"的分支，已删除：判定依据是
「包装在哪」而不是「你在哪」，同一个命令会解析到两个库，`uv run pm import <导出文件>`
能静默造出第二个真库。）

密码库落在仓库外也更安全：仓库里的文件被 `.gitignore` 保护不被提交，但同样的忽略规则
使它成了"清理时无所谓"的目录，`git clean -xfd` 或一次删仓库就会连库一起带走。

`.gitignore` 仍然忽略 `data/` 与 `*.pmv`，作为额外保险。

## 备份

主库永远只有一份（`~/.pm/vault.pmv`），备份是**单向的密文副本**。每次写操作成功后自动
复制一份带时间戳的副本，复制完在终端/网页上提示一行。

| 指定方式 | 备份目录 |
|---|---|
| `--to 目录` / `pm backup` | 命令行指定的目录 |
| `PM_BACKUP_DIR=/x` | `/x` |
| 什么都没给 | `iCloud Drive/pm-backup`（没有 iCloud 时退回 `~/.pm/backup`） |

```bash
pm backup              # 立刻备份一次
pm backup --list       # 看现有备份（时间 / 文件名 / 大小）
pm backup --keep 7     # 只保留最新 7 份（默认 30，0 表示不限）
pm add ... --no-backup # 这一次不备份；PM_NO_BACKUP=1 全局关闭
```

三条刻意的取舍：

- **备份不需要主密码**。搬的是 AES-256-GCM 密文，所以备份路径上没有任何能解锁保险库的
  材料——这也是不选对象存储同步的原因：那会把一个账号级 AK/SK 变成保险库路径上的依赖。
- **只往外复制，不做双向同步**。把主路径指到 iCloud Drive 会引入三个坑：文件被"优化存储"
  变成 dataless 占位符后离线读不到、File Provider 的异步语义破坏 `os.replace` 的原子性、
  两台机器同指一个文件时整包互相覆盖。`PM_HOME` 指到 CloudDocs 是能跑的，但别这么用。
- **备份失败不影响写操作**。备份在保险库落盘之后执行，任何异常只变成一行警告，不回滚写入。

轮转只删匹配 `pm-*.pmv` 的文件，保留最新 N 份；放进该目录的其它文件一律不碰。
`pm backup` 每次都会比对副本与源的 sha256，不一致就丢弃副本并报错——一份不可靠的备份
比没有备份更危险。

恢复就是把备份文件拷回去：

```bash
cp ~/Library/Mobile\ Documents/com~apple~CloudDocs/pm-backup/pm-20260921-204512.pmv ~/.pm/vault.pmv
```

## 回归测试

```bash
uv run python qa/run_tests.py          # 全部断言（CLI + Web）
uv run python qa/run_tests.py --cli    # 只跑 CLI
uv run python qa/run_tests.py --web    # 只跑 Web（会自己起服务、用完关掉）
```

测试用的 1PUX 导出包不在仓库里，通过 `--pux <文件>` 或 `PM_QA_PUX` 环境变量指定；
没有它导入相关的断言无法跑，会直接退出。
测试自建临时保险库、真实导入 1PUX、真实落盘真实发 HTTP，跑完自动清理。
覆盖：密文里搜不到明文、导入幂等、打码不泄露、错误主密码被拒、剪贴板超时清空、
CSRF/跨站拒绝、reveal 开关、增删改与密码历史、导出权限 0600、默认路径与调用方式无关。

比对具体值（密码、字段标签）的断言一律对着**合成的假条目**，真实导出只用于
验证与内容无关的行为——真实密码不该出现在测试代码里。

被测进程走 `PYTHONPATH=src`，直接跑**当前源码**——改完代码不用先 `uv sync` 就能测到，
也不会出现"对着 `.venv` 里的旧副本全绿"。

## 开发

```bash
uv sync --no-editable        # 改完源码要重跑才生效（uv_build 的可编辑安装在本机不可用）
uv run pm <命令>
uv run python qa/run_tests.py
```

`uv run pm` 走的是 `.venv` 里那份拷贝，改源码后需重新 `uv sync --no-editable`；
想直接跑源码可以用 `PYTHONPATH=src uv run pm <命令>`。

改了代码后要更新全局命令：`uv tool install --force .`

### 已知环境坑

* **setuptools 的可编辑安装在 macOS 上会报 `EEXIST: file already exists, mkdir`**，
  非可编辑构建正常。因此本项目用 `uv_build` 后端 + `src/` 布局，`uv sync` 之后
  改源码需要重新 `uv sync --no-editable` 才会生效。
* 模块划分：`crypto`（密钥与加密）、`models`（数据模型与分类映射）、`audit`
  （强度评估）、`vault`（保险库读写）、`importer`（1PUX/CSV）、`ui`（终端渲染）、
  `cli`（子命令）、`webapp`（Flask）。
* 1PUX 的 `date` 字段纪元不统一：实测 `1381449539` 按 Unix 是 2013 年（合理），
  而 `485265660` 按 Unix 是 1985 年（荒谬）、按 Core Foundation 纪元才是 2016 年。
  `models.decode_date()` 做双解释校验后再取合理值。
* 1PUX 的分类 UUID 里 `109` 是 **Wireless Router** 而不是 API Credential。
  `models.CATEGORIES` 里标 `verified=True` 的条目都在真实导出里核对过字段模板。

