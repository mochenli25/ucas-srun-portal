# -*- coding: utf-8 -*-
"""
凭证管理模块
- 使用 cryptography 库的 Fernet 认证加密 (AES-128-CBC + HMAC-SHA256)
- 随机密钥保存在独立的密钥文件, 与凭证密文文件分离
- 两个文件均通过 NTFS 权限限制为仅当前 Windows 用户可访问

文件说明 (均位于脚本同目录):
  .srun.key              Fernet 密钥 (丢了只能重新配置, 泄露=凭证泄露, 切勿提交 git)
  .srun_credentials.enc  账号密码的加密密文 (可随项目备份, 但没有 key 无法解密)
"""

import os
import json
import getpass
import subprocess
import getpass as _gp
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

# 与本文件同目录
_BASE_DIR = Path(__file__).resolve().parent
KEY_FILE = _BASE_DIR / ".srun.key"
CRED_FILE = _BASE_DIR / ".srun_credentials.enc"

# 认证相关非敏感默认值
DEFAULT_AC_ID = "1"
DEFAULT_PORTAL_HOST = "portal.ucas.ac.cn"
DEFAULT_DOMAIN = "@mails.ucas.ac.cn"  # 备选: @ucas.ac.cn


# ======================== 文件权限 ========================
def _restrict_to_current_user(path: Path) -> None:
    """
    将文件 NTFS 权限收紧为仅当前 Windows 用户可访问
    (关闭继承, 移除其他用户, 授予当前用户完全控制)
    """
    user = os.environ.get("USERNAME") or _gp.getuser()
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(F)"],
            capture_output=True, check=True,
        )
    except Exception:
        # 权限收紧失败不阻塞主流程 (例如非 Windows / 非 NTFS)
        print(f"  [!] 警告: 未能收紧 {path.name} 的访问权限, 请自行确保其安全")


# ======================== 密钥管理 ========================
def _load_or_create_key() -> bytes:
    """读取 Fernet 密钥; 不存在则生成新密钥并落盘"""
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes().strip()

    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    _restrict_to_current_user(KEY_FILE)
    return key


def _get_fernet() -> Fernet:
    return Fernet(_load_or_create_key())


# ======================== 凭证读写 ========================
def save_credentials(username: str, password: str,
                     domain: str = DEFAULT_DOMAIN,
                     ac_id: str = DEFAULT_AC_ID) -> None:
    """将完整凭证 JSON 加密后写入密文文件"""
    payload = json.dumps({
        "username": username,
        "password": password,
        "domain": domain,
        "ac_id": ac_id,
    }, ensure_ascii=False).encode("utf-8")

    token = _get_fernet().encrypt(payload)
    CRED_FILE.write_bytes(token)
    _restrict_to_current_user(CRED_FILE)


def load_credentials(auto_prompt: bool = True) -> dict:
    """
    读取并解密凭证
    返回: {"username", "password", "domain", "ac_id", "portal_host"}
    若凭证文件不存在且 auto_prompt=True, 则引导用户输入
    """
    if not CRED_FILE.exists() or not KEY_FILE.exists():
        if not auto_prompt:
            missing = KEY_FILE.name if not KEY_FILE.exists() else CRED_FILE.name
            raise FileNotFoundError(f"凭证相关文件不存在: {missing}")
        return setup_credentials_interactive()

    try:
        payload = _get_fernet().decrypt(CRED_FILE.read_bytes())
    except InvalidToken:
        raise PermissionError(
            "凭证解密失败: 密钥与密文不匹配 (.srun.key 可能被更换), "
            "请运行 config.py 重新配置"
        )

    cred = json.loads(payload.decode("utf-8"))
    cred.setdefault("domain", DEFAULT_DOMAIN)
    cred.setdefault("ac_id", DEFAULT_AC_ID)
    cred["portal_host"] = DEFAULT_PORTAL_HOST
    return cred


def setup_credentials_interactive() -> dict:
    """首次使用时引导输入账号密码并加密保存"""
    print("=" * 60)
    print("  首次使用: 配置账号信息 (仅需一次, 将加密存储)")
    print("=" * 60)
    username = input("  账号 (不含 @域名): ").strip()
    domain = input(f"  域名后缀 (回车默认 {DEFAULT_DOMAIN}): ").strip() or DEFAULT_DOMAIN
    password = getpass.getpass("  密码 (输入时不显示): ")

    if not username or not password:
        print("  [X] 账号和密码不能为空")
        raise SystemExit(1)

    save_credentials(username, password, domain)
    print(f"\n  [OK] 凭证已加密保存:")
    print(f"       密钥文件: {KEY_FILE.name}")
    print(f"       密文文件: {CRED_FILE.name}")

    return {
        "username": username,
        "password": password,
        "domain": domain,
        "ac_id": DEFAULT_AC_ID,
        "portal_host": DEFAULT_PORTAL_HOST,
    }


def reset_credentials() -> None:
    """删除旧密文并重新配置 (保留同一把密钥)"""
    if CRED_FILE.exists():
        CRED_FILE.unlink()
    setup_credentials_interactive()


if __name__ == "__main__":
    import sys
    # 直接运行本文件: 查看凭证状态; --reset 重新配置
    if "--reset" in sys.argv:
        reset_credentials()
    elif CRED_FILE.exists() and KEY_FILE.exists():
        try:
            c = load_credentials(auto_prompt=False)
            print(f"  密钥文件: {KEY_FILE}")
            print(f"  密文文件: {CRED_FILE}")
            print(f"  账号: {c['username']}{c['domain']}")
            print(f"  ac_id: {c['ac_id']}")
            print("  密码: ******** (已加密)")
        except Exception as e:
            print(f"  [!] 现有凭证无法读取: {e}")
            ans = input("  是否重新配置? (y/N): ").strip().lower()
            if ans == "y":
                setup_credentials_interactive()
    else:
        setup_credentials_interactive()
