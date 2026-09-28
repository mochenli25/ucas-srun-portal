# -*- coding: utf-8 -*-
"""
登出 -> 登录 完整闭环测试
注意: 本脚本会先断网(登出)再认证(登录), 期间无法访问外网!
请确认当前网络仅用于测试, 并自行手动运行:
    venv\Scripts\python.exe test_login.py
"""

import time

import config
from srun_login import SrunClient


def main():
    cred = config.load_credentials()
    client = SrunClient(cred)

    # === 步骤1: 记录当前在线信息 ===
    print("=== 步骤1: 查询当前在线状态 ===")
    online, ip = client.check_online()
    if not online:
        print("  当前不在线, 跳过登出, 直接测试登录")
        ip = client.detect_ip()
    else:
        print(f"  在线 IP: {ip}")

        # === 步骤2: 登出 ===
        print("\n=== 步骤2: 登出 ===")
        client.logout(ip=ip)
        print("  等待 2 秒...")
        time.sleep(2)

        print("\n=== 步骤3: 验证离线状态 ===")
        online_after_logout, _ = client.check_online()
        print(f"  在线状态: {online_after_logout}")

        print("\n=== 步骤4: 重新检测 IP ===")
        ip = client.detect_ip() or ip

    # === 步骤5: 自动登录 ===
    print("\n=== 步骤5: 脚本自动登录 ===")
    print(f"  使用 IP: {ip}")
    success = client.login(ip)

    if not success:
        alt = "@ucas.ac.cn" if client.domain != "@ucas.ac.cn" else "@mails.ucas.ac.cn"
        print(f"\n  主域名失败, 尝试备用域名 {alt} ...")
        success = client.login(ip, domain=alt)

    # === 步骤6: 验证在线 ===
    print("\n=== 步骤6: 验证在线状态 ===")
    time.sleep(1)
    online_final, final_ip = client.check_online()
    print(f"  在线状态: {online_final}, IP: {final_ip}")

    print("\n" + ("=" * 50))
    print("  闭环测试成功!" if success and online_final else "  闭环测试失败!")
    print("=" * 50)


if __name__ == "__main__":
    main()
