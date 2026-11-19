"""password-manager —— 本地优先的加密密码保险库。

模块划分：
    crypto    Argon2id 密钥派生 + AES-256-GCM 整体加密，macOS Keychain 密钥缓存
    models    Item / Field 数据模型与 1Password 分类映射、字段值变体解码
    audit     密码强度评估与安全审计
    vault     加密保险库的读写、CRUD、搜索
    importer  1PUX / CSV 导入器
"""

__version__ = "0.1.5"

APP_NAME = "pm"
APP_TITLE = "password-manager"

#: 保险库文件格式标识，位于密文文件首部
VAULT_MAGIC = b"PMVAULT\x00"

#: 当前保险库格式版本
VAULT_FORMAT_VERSION = 1

#: 网络锁定时长（秒），Web 空闲多久后自动清除内存中的密钥
DEFAULT_IDLE_LOCK = 600
