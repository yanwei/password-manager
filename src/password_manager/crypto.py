"""加密层 —— Argon2id 密钥派生 + AES-256-GCM 整体加密 + macOS Keychain 密钥缓存。

设计要点
--------
* **整体加密**：整个保险库 payload 序列化成 JSON 后被一次性加密，磁盘上
  不存在任何明文、明文索引或可枚举的结构。密文的 GCM 认证标签同时承担
  「主密码是否正确」的校验职责——不需要单独存校验和。
* **定长头部**：文件首部是固定 49 字节的二进制头，解析不依赖任何解析器，
  也便于未来版本兼容。
* **密钥缓存是可选的加速手段**：Keychain 不可用、被拒绝或过期时静默降级为
  交互式输入，绝不因为缓存失败而阻塞主流程。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import struct
import subprocess
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from . import VAULT_FORMAT_VERSION, VAULT_MAGIC

# ── 参数 ─────────────────────────────────────────────────────────────────────

ARGON2_ITERATIONS = 3
ARGON2_MEMORY_KIB = 65536  # 64 MiB
ARGON2_LANES = 4
KEY_LEN = 32  # AES-256
SALT_LEN = 16
NONCE_LEN = 12

#: 定长头部：magic(8) | version(1) | iterations(4) | memory(4) | lanes(4) | salt(16) | nonce(12)
_HEADER = struct.Struct(f">8sBIII{SALT_LEN}s{NONCE_LEN}s")
HEADER_LEN = _HEADER.size  # 49

#: Keychain 中存放缓存密钥的服务名
KEYCHAIN_SERVICE = "pm-vault"

KEYCHAIN_DEFAULT_TTL = 900  # 15 分钟


class VaultError(Exception):
    """保险库层的通用错误。"""


class WrongPassword(VaultError):
    """主密码错误，或密文已被篡改。"""


class VaultNotFound(VaultError):
    """保险库文件不存在。"""


# ── 密钥派生 ─────────────────────────────────────────────────────────────────


def derive_key(
    password: str,
    salt: bytes,
    *,
    iterations: int = ARGON2_ITERATIONS,
    memory_cost: int = ARGON2_MEMORY_KIB,
    lanes: int = ARGON2_LANES,
) -> bytes:
    """用 Argon2id 从主密码派生 32 字节密钥。"""
    kdf = Argon2id(
        salt=salt,
        length=KEY_LEN,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_payload(payload: dict, key: bytes) -> bytes:
    """把 payload 加密成一个完整的保险库字节串。"""
    salt = os.urandom(SALT_LEN)
    return encrypt_with_salt(payload, key, salt)


def encrypt_with_salt(payload: dict, key: bytes, salt: bytes) -> bytes:
    """用给定 salt 加密（salt 已在头部，派生时复用同一把 key）。"""
    nonce = os.urandom(NONCE_LEN)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    header = _HEADER.pack(
        VAULT_MAGIC,
        VAULT_FORMAT_VERSION,
        ARGON2_ITERATIONS,
        ARGON2_MEMORY_KIB,
        ARGON2_LANES,
        salt,
        nonce,
    )
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _aad(header))
    return header + ciphertext


def _aad(header: bytes) -> bytes:
    """把头部绑定为附加认证数据，防止参数被改写降级。"""
    return header


@dataclass(frozen=True)
class Header:
    """解析出的保险库头部。"""

    version: int
    iterations: int
    memory_cost: int
    lanes: int
    salt: bytes
    nonce: bytes
    raw: bytes


def parse_header(blob: bytes) -> Header:
    """解析并校验保险库头部。"""
    if len(blob) < HEADER_LEN:
        raise VaultError("保险库文件不完整（长度不足）。")
    magic, version, iterations, memory, lanes, salt, nonce = _HEADER.unpack_from(blob, 0)
    if magic != VAULT_MAGIC:
        raise VaultError("这不是 pm 保险库文件（magic 不匹配）。")
    if version > VAULT_FORMAT_VERSION:
        raise VaultError(
            f"保险库格式版本 {version} 高于本程序支持的 {VAULT_FORMAT_VERSION}，请升级 pm。"
        )
    return Header(
        version=version,
        iterations=iterations,
        memory_cost=memory,
        lanes=lanes,
        salt=salt,
        nonce=nonce,
        raw=blob[:HEADER_LEN],
    )


def decrypt_payload(blob: bytes, key: bytes) -> dict:
    """用已派生的密钥解密整个保险库。"""
    header = parse_header(blob)
    ciphertext = blob[HEADER_LEN:]
    try:
        plaintext = AESGCM(key).decrypt(header.nonce, ciphertext, _aad(header.raw))
    except InvalidTag as exc:  # 密码错 or 密文被改
        raise WrongPassword("主密码错误，或保险库文件已被篡改。") from exc
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultError("保险库内容损坏，无法解析。") from exc


def key_fingerprint(key: bytes) -> str:
    """密钥指纹，仅用于展示与调试，不可反推密钥。"""
    return hashlib.sha256(key).hexdigest()[:16]


# ── macOS Keychain 密钥缓存 ──────────────────────────────────────────────────
#
# 缓存的内容是**派生后的密钥**而非主密码：主密码从不出现在钥匙串里。
# 条目里额外记录过期时间与保险库路径，避免把 A 库的密钥用到 B 库上
# （即便真的用错了，GCM 认证标签也会直接失败）。


def keychain_available() -> bool:
    """当前平台是否支持钥匙串缓存。"""
    return platform.system() == "Darwin"


def _security(*args: str, timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["security", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _account_for(vault_path: str) -> str:
    return os.path.abspath(vault_path)


def keychain_store(vault_path: str, key: bytes, ttl: int = KEYCHAIN_DEFAULT_TTL) -> bool:
    """把派生密钥写入钥匙串，ttl 秒后失效。成功返回 True。"""
    if not keychain_available():
        return False
    blob = json.dumps(
        {
            "key": base64.b64encode(key).decode("ascii"),
            "expires": time.time() + ttl,
            "vault": os.path.abspath(vault_path),
        }
    )
    try:
        proc = _security(
            "add-generic-password",
            "-U",  # 已存在则更新
            "-a", _account_for(vault_path),
            "-s", KEYCHAIN_SERVICE,
            "-l", f"pm 缓存密钥 · {os.path.basename(vault_path)}",
            "-D", "pm vault key cache",
            "-w", blob,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return proc.returncode == 0


def keychain_load(vault_path: str) -> bytes | None:
    """读取并校验缓存的密钥；不存在、过期或任何异常一律返回 None。"""
    if not keychain_available():
        return None
    try:
        proc = _security(
            "find-generic-password",
            "-a", _account_for(vault_path),
            "-s", KEYCHAIN_SERVICE,
            "-w",
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout.strip())
        if data.get("vault") and os.path.abspath(data["vault"]) != os.path.abspath(vault_path):
            return None
        if float(data.get("expires", 0)) < time.time():
            keychain_clear(vault_path)
            return None
        key = base64.b64decode(data["key"])
    except (ValueError, KeyError, TypeError):
        keychain_clear(vault_path)
        return None
    return key if len(key) == KEY_LEN else None


def keychain_clear(vault_path: str) -> None:
    """清除缓存密钥。不存在也算成功。"""
    if not keychain_available():
        return
    try:
        _security(
            "delete-generic-password",
            "-a", _account_for(vault_path),
            "-s", KEYCHAIN_SERVICE,
        )
    except (subprocess.SubprocessError, OSError):
        pass
