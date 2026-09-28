# -*- coding: utf-8 -*-
"""
UCAS 深澜(Srun) Portal 登出脚本
- 从加密凭证读取账号
- 优先使用 rad_user_info 返回的实际在线用户名/IP 登出 (域名最可靠)
"""

import config
from srun_login import SrunClient, parse_jsonp


def get_online_info(client: SrunClient) -> dict:
    """获取完整在线信息 (user_name, online_ip 等)"""
    params = {"callback": "jsonp", "_": client._ts()}
    r = client.session.get(f"{client.base_url}/cgi-bin/rad_user_info",
                           params=params, timeout=5)
    return parse_jsonp(r.text)


def main():
    print("=" * 60)
    print("  UCAS 深澜 Portal 登出")
    print("=" * 60)

    cred = config.load_credentials()
    client = SrunClient(cred)

    print("\n[步骤1] 查询在线状态...")
    info = get_online_info(client)

    if info.get("error") != "ok":
        print("  [√] 当前不在线, 无需登出")
        return True

    online_user = info.get("user_name", client.full_username)
    online_ip = info.get("online_ip", "")

    # 在线用户名形如 "账号@域名", 解析出域名后缀
    if "@" in online_user:
        base, domain = online_user.split("@", 1)
        domain = "@" + domain
    else:
        base, domain = online_user, client.domain

    print(f"  [*] 在线账号: {online_user}")
    print(f"  [*] 在线 IP: {online_ip}")

    # 安全校验: 在线账号应与凭证账号一致
    mismatch = base != client.username
    if mismatch:
        print(f"  [!] 注意: 当前在线账号 {base} 与凭证账号 {client.username} 不同")
    prompt = "  确认登出? 登出后将断网 (y/N): " if not mismatch else "  仍要登出该在线账号吗? (y/N): "
    if input(prompt).strip().lower() != "y":
        print("  已取消")
        return False

    print("\n[步骤2] 执行登出...")
    ok = client.logout(ip=online_ip, domain=domain)

    print("\n" + "=" * 60)
    print("  登出成功!" if ok else "  登出失败!")
    print("=" * 60)
    return ok


if __name__ == "__main__":
    main()
