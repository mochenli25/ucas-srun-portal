# -*- coding: utf-8 -*-
"""
UCAS 深澜(Srun) Portal 自动认证脚本
流程: 检测在线状态 -> 获取 IP -> 获取 challenge token -> 加密 -> 登录
账号密码从加密凭证读取 (见 config.py), 本文件不含任何明文敏感信息
"""

import re
import json
import time
import hmac
import hashlib
import requests

import config

# ======================== 自定义 Base64 ========================
SRUN_B64_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

def srun_base64_encode(data: bytes) -> str:
    """使用 Srun 自定义字母表进行 Base64 编码"""
    alpha = SRUN_B64_ALPHA
    result = []
    i = 0
    while i < len(data):
        chunk = data[i:i+3]
        n = 0
        for j, byte in enumerate(chunk):
            n |= byte << (16 - j * 8)
        result.append(alpha[(n >> 18) & 0x3F])
        result.append(alpha[(n >> 12) & 0x3F])
        if len(chunk) > 1:
            result.append(alpha[(n >> 6) & 0x3F])
        else:
            result.append('=')
        if len(chunk) > 2:
            result.append(alpha[n & 0x3F])
        else:
            result.append('=')
        i += 3
    return ''.join(result)

# ======================== XXTEA 加密 ========================
def _str_to_int_array(s: str, append_length: bool):
    """将字符串转换为 32 位无符号整数数组 (对应 JS 的 s 函数)"""
    v = []
    raw = s.encode('latin-1') if isinstance(s, str) else s
    c = len(raw)
    i = 0
    while i < c:
        b0 = raw[i] if i < c else 0
        b1 = raw[i+1] if i+1 < c else 0
        b2 = raw[i+2] if i+2 < c else 0
        b3 = raw[i+3] if i+3 < c else 0
        val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        v.append(val & 0xFFFFFFFF)
        i += 4
    if append_length:
        v.append(c & 0xFFFFFFFF)
    return v

def _int_array_to_str(v) -> str:
    """将整数数组转换回字符串 (对应 JS 的 l 函数, b=False)"""
    result = []
    for val in v:
        result.append(chr(val & 0xFF))
        result.append(chr((val >> 8) & 0xFF))
        result.append(chr((val >> 16) & 0xFF))
        result.append(chr((val >> 24) & 0xFF))
    return ''.join(result)

def xxtea_encrypt(str_data: str, key_data: str) -> str:
    """XXTEA 加密, 移植自 Srun Portal 的 encode 函数"""
    if not str_data:
        return ''

    v = _str_to_int_array(str_data, True)
    k = _str_to_int_array(key_data, False)
    while len(k) < 4:
        k.append(0)

    n = len(v) - 1
    if n < 0:
        return ''
    z = v[n]
    y = v[0]
    delta = 0x9E3779B9  # 0x86014019 | 0x183639A0
    mask = 0xFFFFFFFF
    q = 6 + 52 // (n + 1)
    d = 0

    while q > 0:
        d = (d + delta) & mask
        e = (d >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            m = (z >> 5) ^ ((y << 2) & mask)
            m = (m + (((y >> 3) ^ ((z << 4) & mask) ^ ((d ^ y) & mask)) & mask)) & mask
            m = (m + (k[(p & 3) ^ e] ^ z)) & mask
            z = v[p] = (v[p] + m) & mask
        # p == n
        y = v[0]
        m = (z >> 5) ^ ((y << 2) & mask)
        m = (m + (((y >> 3) ^ ((z << 4) & mask) ^ ((d ^ y) & mask)) & mask)) & mask
        m = (m + (k[(n & 3) ^ e] ^ z)) & mask
        z = v[n] = (v[n] + m) & mask
        q -= 1

    return _int_array_to_str(v)

# ======================== Srun 信息编码 ========================
def encode_user_info(info_dict: dict, token: str) -> str:
    """编码用户信息: {SRBX1} + srun_base64(xxtea(json, token))"""
    info_json = json.dumps(info_dict, separators=(',', ':'))
    encrypted = xxtea_encrypt(info_json, token)
    encrypted_bytes = encrypted.encode('latin-1')
    encoded = srun_base64_encode(encrypted_bytes)
    return '{SRBX1}' + encoded

# ======================== JSONP 解析 ========================
def parse_jsonp(text: str) -> dict:
    """从 JSONP 响应中提取 JSON"""
    match = re.search(r'\((\{.*\})\)', text, re.DOTALL)
    if match:
        return json.loads(match.group(1))
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}

# ======================== Portal 客户端 ========================
class SrunClient:
    """封装与 Srun Portal 的全部交互"""

    def __init__(self, cred: dict):
        self.username = cred["username"]
        self.password = cred["password"]
        self.domain = cred["domain"]
        self.ac_id = cred["ac_id"]
        self.base_url = f"https://{cred['portal_host']}"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36"
        })

    @staticmethod
    def _ts():
        return str(int(time.time() * 1000))

    @property
    def full_username(self) -> str:
        return self.username + self.domain

    # ---------- 状态 / IP ----------
    def check_online(self) -> tuple:
        """返回 (is_online: bool, ip: str)"""
        params = {"callback": "jsonp", "_": self._ts()}
        try:
            r = self.session.get(f"{self.base_url}/cgi-bin/rad_user_info",
                                 params=params, timeout=5)
            data = parse_jsonp(r.text)
            if data.get("error") == "ok":
                return True, data.get("online_ip", "")
            ip = data.get("client_ip", data.get("online_ip", ""))
            return False, ip
        except Exception as e:
            print(f"  [!] 查询在线状态失败: {e}")
            return False, ""

    def detect_ip(self) -> str:
        """检测当前内网 IP: 优先利用未认证时的网关重定向"""
        try:
            r = self.session.get("http://www.baidu.com",
                                 allow_redirects=False, timeout=5)
            if r.status_code in (301, 302):
                location = r.headers.get("Location", "")
                for pattern in (r'[?&]user_ip=([0-9a-fA-F.:]+)',
                                r'[?&]ip=([0-9a-fA-F.:]+)'):
                    match = re.search(pattern, location)
                    if match:
                        ip = match.group(1)
                        print(f"  [+] 从重定向检测到 IP: {ip}")
                        return ip
        except Exception:
            pass

        _, ip = self.check_online()
        if ip:
            print(f"  [+] 从 rad_user_info 检测到 IP: {ip}")
            return ip
        return ""

    # ---------- 认证原语 ----------
    def get_challenge(self, full_username: str, ip: str) -> str:
        """获取 challenge token"""
        params = {
            "callback": "jsonp",
            "username": full_username,
            "ip": ip,
            "_": self._ts(),
        }
        r = self.session.get(f"{self.base_url}/cgi-bin/get_challenge",
                             params=params, timeout=5)
        data = parse_jsonp(r.text)
        challenge = data.get("challenge", "")
        if data.get("error") and data.get("error") != "ok":
            print(f"  [!] get_challenge: error={data.get('error')}, "
                  f"error_msg={data.get('error_msg', '')}")
        if not challenge:
            print(f"  [!] get_challenge 原始响应: {r.text[:300]}")
        return challenge

    # ---------- 登录 / 登出 ----------
    def login(self, ip: str, domain: str = None) -> bool:
        """执行登录; domain 可临时覆盖 (用于备用域名重试)"""
        domain = domain if domain is not None else self.domain
        full_username = self.username + domain
        print(f"  [*] 用户名: {full_username}")
        print(f"  [*] IP: {ip or '(空)'}")

        print("  [1] 获取 challenge token...")
        token = self.get_challenge(full_username, ip)
        if not token:
            print("  [X] 获取 challenge token 失败!")
            return False
        print(f"  [+] Token: {token[:20]}...")

        hmd5 = hmac.new(token.encode(), self.password.encode(),
                        hashlib.md5).hexdigest()

        info_dict = {
            "username": full_username,
            "password": self.password,
            "ip": ip,
            "acid": self.ac_id,
            "enc_ver": "srun_bx1",
        }
        encoded_info = encode_user_info(info_dict, token)

        n, type_ = "200", "1"
        chk_str = token + full_username
        chk_str += token + hmd5
        chk_str += token + self.ac_id
        chk_str += token + ip
        chk_str += token + n
        chk_str += token + type_
        chk_str += token + encoded_info
        chksum = hashlib.sha1(chk_str.encode()).hexdigest()

        print("  [2] 发送登录请求...")
        params = {
            "callback": "jsonp",
            "action": "login",
            "username": full_username,
            "password": "{MD5}" + hmd5,
            "os": "Windows 10",
            "name": "Windows",
            "double_stack": "0",
            "chksum": chksum,
            "info": encoded_info,
            "ac_id": self.ac_id,
            "ip": ip,
            "n": n,
            "type": type_,
            "_": self._ts(),
        }
        r = self.session.get(f"{self.base_url}/cgi-bin/srun_portal",
                             params=params, timeout=10)
        data = parse_jsonp(r.text)

        error = data.get("error", "")
        error_msg = data.get("error_msg", "")
        ploy_msg = data.get("ploy_msg", "")

        if error == "ok":
            print(f"  [OK] 登录成功! (error={error})")
            return True

        print("  [X] 登录失败!")
        print(f"  [X] error={error}, error_msg={error_msg}")
        if ploy_msg:
            print(f"  [X] ploy_msg={ploy_msg}")
        print(f"  [X] 完整响应: {r.text[:500]}")
        return False

    def logout(self, ip: str = None, domain: str = None) -> bool:
        """执行登出"""
        domain = domain if domain is not None else self.domain
        full_username = self.username + domain
        if ip is None:
            _, ip = self.check_online()
        print(f"  [*] 登出用户: {full_username}")
        print(f"  [*] IP: {ip or '(空)'}")

        params = {
            "callback": "jsonp",
            "action": "logout",
            "username": full_username,
            "ip": ip or "",
            "ac_id": self.ac_id,
            "_": self._ts(),
        }
        r = self.session.get(f"{self.base_url}/cgi-bin/srun_portal",
                             params=params, timeout=10)
        data = parse_jsonp(r.text)
        error = data.get("error", "")
        if error == "ok":
            print("  [OK] 登出成功!")
            return True
        print(f"  [X] 登出失败: error={error}, "
              f"error_msg={data.get('error_msg', '')}")
        print(f"  [X] 完整响应: {r.text[:500]}")
        return False

# ======================== 主流程 ========================
def main():
    print("=" * 60)
    print("  UCAS 深澜 Portal 自动认证")
    print("=" * 60)

    cred = config.load_credentials()
    client = SrunClient(cred)

    print("\n[步骤1] 检查在线状态...")
    online, known_ip = client.check_online()
    if online:
        print("  [√] 已在线, 无需认证!")
        return True

    print("\n[步骤2] 检测 IP 地址...")
    ip = known_ip or client.detect_ip()
    if not ip:
        print("  [!] 无法检测到 IP, 尝试用空 IP 登录...")

    print("\n[步骤3] 执行认证...")
    if client.login(ip):
        print("\n" + "=" * 60)
        print("  认证成功!")
        print("=" * 60)
        return True

    # 备用域名重试
    alt_domain = "@ucas.ac.cn" if client.domain != "@ucas.ac.cn" else "@mails.ucas.ac.cn"
    print(f"\n[重试] 尝试域名 {alt_domain}...")
    if client.login(ip, domain=alt_domain):
        print("\n" + "=" * 60)
        print("  认证成功!")
        print("=" * 60)
        return True

    print("\n" + "=" * 60)
    print("  认证失败, 请检查网络连接和账号信息 (可运行 config.py 重新配置)")
    print("=" * 60)
    return False

if __name__ == "__main__":
    main()
