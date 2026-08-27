# Key Managerment — 网页版 SSH 私钥生成与公钥部署工具

一个自托管的 Web 工具：在网页上**生成 SSH 私钥**（发起端），并**把公钥部署**到目标主机（接受端），实现免密登录。支持 Windows / Linux 作为发起端，支持 Linux / RouterOS (MikroTik) 作为接受端。

## 功能特性

- **发起端生成私钥**
  - 平台可选：Windows / Linux。
  - 密钥类型可选：Ed25519（推荐）/ RSA 3072。
  - 服务端自动 SSH 登录发起端，在 `~/.ssh/` 下生成密钥对（Windows 为 `%USERPROFILE%\.ssh\`）。
- **接受端部署公钥**
  - 平台可选：Linux / RouterOS (MikroTik)。
  - 公钥自动取自发起端，也可手动粘贴。
  - Linux 写入 `~/.ssh/authorized_keys`；RouterOS 写入 `/user ssh-keys`（自动兼容新旧版本 `key=` / `public-key=` 参数）。
- **历史私钥库**
  - 生成的私钥（加密保存）+ 公钥 + 发起端信息自动入库。
  - 网页下拉选择历史密钥即自动填充全部信息，可一键把对应公钥重新部署到新机器。
  - 支持复制私钥/公钥内容、删除历史记录。
- **安全设计**
  - 管理员登录鉴权 + CSRF 防护 + 登录失败锁定。
  - 私钥以 Fernet(AES) 加密存储于服务端 `keystore.json`（权限 600）。
  - 远程命令均做 shell 安全引用；Windows 侧命令通过 PowerShell EncodedCommand 执行，兼容 cmd 默认 shell。

## 一键安装（systemd / Linux）

在 Debian / Ubuntu / CentOS / RHEL 上以 **root** 执行（自动下载最新 Release 并安装、开机自启）：

```bash
sudo bash -c "$(curl -fsSL https://github.com/driftbottle61/key-managerment/releases/latest/download/key-managerment-latest.tar.gz)"
```
> 上面一行是直接下载并解压的示意；更稳妥的方式是手动下载 tar.gz 后解压再执行 `install.sh`。

**手动安装**

1. 下载安装包并解压：
   ```bash
   wget https://github.com/driftbottle61/key-managerment/releases/latest/download/key-managerment-latest.tar.gz
   tar -xzf key-managerment-latest.tar.gz
   cd key-managerment-v1.0.0
   ```
2. 执行一键安装（root）：
   ```bash
   sudo bash install.sh              # 默认端口 8080, 管理员 admin
   SSHWEB_PORT=8800 sudo bash install.sh   # 自定义端口
   ```
3. 安装脚本会自动：
   - 安装 Python3 / venv / pip 依赖；
   - 创建虚拟环境并安装依赖（Flask, paramiko, cryptography, waitress）；
   - 生成 systemd 服务 `key-managerment` 并**开机自启**；
   - 生成初始管理员密码（写入 `/opt/key-managerment/INITIAL_PASSWORD.txt`）。

安装完成后打开：
```
http://<服务器IP>:8080
```
使用脚本输出的账号密码登录。**首次登录后请修改管理员密码并删除 `INITIAL_PASSWORD.txt`。**

## 手动运行（不使用 systemd）

```bash
cd key-managerment-v1.0.0
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
SSHWEB_PORT=8080 SSHWEB_ADMIN_USER=admin SSHWEB_ADMIN_PASSWORD='你的密码' .venv/bin/python app.py
```

## Docker 运行

```bash
docker build -t key-managerment .
docker run -d --name key-managerment --restart unless-stopped \
  -p 8080:8080 -v /opt/key-managerment-data:/app/data key-managerment
```
> 数据（config.json / keystore.json）持久化在 `/app/data`，请确保该卷权限安全。

## 使用说明

登录后在首页有左右两张卡片：

**① SSH 发起端 · 生成私钥**
1. （可选）从「历史私钥」下拉选择一把曾经生成的密钥，下方信息会自动填充，直接跳到部署。
2. 填写发起端信息：主机 IP、SSH 用户名、端口、密码，选择系统平台（Windows/Linux）和密钥类型。
3. 点「生成私钥」。成功后显示私钥文件路径与公钥，公钥自动填入右侧接受端卡片。

**② SSH 接受端 · 部署公钥**
1. 填写接受端信息：主机 IP、SSH 用户名、端口、密码，选择系统平台（Linux / RouterOS）。
   - RouterOS 可指定「绑定用户」（默认同登录用户名）。
2. 确认「公钥」内容（已自动取自发起端，可手动修改）。
3. 点「部署公钥」。成功后目标主机即可用发起端的私钥免密登录。

**历史私钥下拉**
- 生成过的密钥会出现在「历史私钥」下拉中，选中即自动填充发起端信息与公钥。
- 可复制私钥/公钥内容，也可删除不再需要的记录。

**Windows 发起端前置条件**
- 目标 Windows 需已启用 OpenSSH Server（`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`），并放行防火墙。
- 登录用户需能通过 SSH 登录该 Windows（微软账号请使用其本地/微软账号凭据）。

**RouterOS 接受端前置条件**
- 需允许 SSH 登录（`/ip service set ssh disabled=no`）。
- 如需用密码登录完成首次部署，需开启密码认证；部署完成后可关闭。
- 系统自动用 `key=` 参数写入，旧版本失败时自动回退 `public-key=`。

## 目录结构

```
key-managerment/
├── app.py            # Flask 应用 + API
├── core.py           # 密钥生成 / Linux/RouterOS/Windows 部署逻辑
├── keystore.py       # 加密密钥库(历史私钥)
├── install.sh        # 一键安装脚本(systemd)
├── build.sh          # 打包 Release 脚本
├── requirements.txt  # Python 依赖
├── run.sh            # 直接运行脚本
├── Dockerfile        # 容器化
├── templates/        # 页面模板
└── static/           # 前端 JS/CSS
```

## 数据与安全说明

- **配置文件**：`config.json`（管理员哈希、会话密钥、加密密钥），权限敏感，勿提交仓库。
- **密钥库**：`keystore.json` 保存加密后的私钥，权限 600，切勿外泄。
- 公网部署务必走 HTTPS（反向代理 + Let's Encrypt），不要裸开端口。
- 该工具是敏感运维入口，请仅在受控/授权环境使用。
