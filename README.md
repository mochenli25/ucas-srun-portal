# UCAS 深澜 Portal 自动认证

基于深澜（Srun）认证接口的校园网自动登录/登出脚本，账号密码以 Fernet 加密存储，本地文件中无明文。

## 环境准备（仅首次）

```powershell
# 1. 创建虚拟环境
python -m venv venv

# 2. 安装依赖
venv\Scripts\pip.exe install -r requirements.txt
```

## 配置凭证

```powershell
# 交互式输入账号密码（密码隐藏显示），自动加密保存
venv\Scripts\python.exe config.py --reset
```

凭证生成两个文件（已加入 .gitignore，切勿提交）：

| 文件 | 说明 |
|---|---|
| `.srun.key` | Fernet 密钥，丢失则密文无法解密 |
| `.srun_credentials.enc` | 账号密码密文 |

查看当前凭证状态：`venv\Scripts\python.exe config.py`

## 使用

```powershell
venv\Scripts\python.exe srun_login.py    # 认证（已在线则跳过）
venv\Scripts\python.exe srun_logout.py   # 登出（需输入 y 确认，会断网）
venv\Scripts\python.exe test_login.py    # 登出→登录闭环测试（会短暂断网）
```

## 文件说明

| 文件 | 作用 |
|---|---|
| `config.py` | 凭证加密存储与读取（Fernet + NTFS 权限） |
| `srun_login.py` | 认证主逻辑，封装 `SrunClient`（检测状态/IP、登录、登出） |
| `srun_logout.py` | 登出入口，按在线会话的实际用户名登出 |
| `test_login.py` | 登出再登录的闭环验证 |

## 认证流程

1. `get_challenge` 用账号 + IP 换取一次性 token
2. 用 token 计算 HMAC-MD5（密码）、XXTEA + 自定义 Base64（info）、SHA1（chksum）
3. `srun_portal?action=login` 提交，服务器用同一 token 校验

## 安全提示

- `.srun.key` 与 `.srun_credentials.enc` 不要提交 git、不要外传
- 两个文件已通过 NTFS ACL 限制为仅当前 Windows 用户可读
- 换电脑或换 Windows 用户后需重新 `config.py --reset`
