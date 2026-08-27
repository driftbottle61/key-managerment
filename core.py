# -*- coding: utf-8 -*-
"""核心逻辑: 密钥生成 + SSH 部署(Linux / RouterOS)。"""
import base64
import io
import os
import subprocess
import tempfile
import time
from datetime import datetime

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


class DeployError(Exception):
    pass


# ---------------------------------------------------------------------------
# 密钥生成
# ---------------------------------------------------------------------------

def _set_restrictive_perms(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def generate_keypair(key_type="ed25519", comment=None):
    """生成密钥对到临时目录, 返回 dict(priv_path, pub_path, private, public)。"""
    key_type = key_type or "ed25519"
    if comment is None:
        comment = "web@ssh-deploy"
    tmpdir = tempfile.mkdtemp(prefix="sshweb_key_")
    priv_path = os.path.join(tmpdir, "id_" + key_type)
    pub_path = priv_path + ".pub"

    if HAVE_CRYPTO:
        if key_type == "ed25519":
            key = ed25519.Ed25519PrivateKey.generate()
        elif key_type == "rsa":
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        else:
            raise DeployError("不支持的密钥类型: %s" % key_type)
        private = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        public = key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode("ascii").rstrip("\n") + " " + comment + "\n"
        with open(priv_path, "w", encoding="utf-8") as f:
            f.write(private)
        with open(pub_path, "w", encoding="utf-8") as f:
            f.write(public)
    else:
        subprocess.run(
            ["ssh-keygen", "-t", key_type, "-f", priv_path, "-N", "", "-C", comment],
            check=True,
        )
        with open(priv_path, "r", encoding="utf-8") as f:
            private = f.read()
        with open(pub_path, "r", encoding="utf-8") as f:
            public = f.read()
    _set_restrictive_perms(priv_path)
    return {
        "key_type": key_type,
        "priv_path": priv_path,
        "pub_path": pub_path,
        "private": private,
        "public": public,
    }


# ---------------------------------------------------------------------------
# 公钥解析
# ---------------------------------------------------------------------------

VALID_TYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
               "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521")


def parse_pubkey(text):
    """从文本中解析第一行合法公钥, 返回 'type base64'。"""
    if not text:
        raise DeployError("公钥内容为空")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in VALID_TYPES:
            return " ".join(parts[:2])
    raise DeployError("未找到合法的 SSH 公钥")


# ---------------------------------------------------------------------------
# SSH 连接与执行
# ---------------------------------------------------------------------------

def _load_pkey(content):
    import paramiko
    content = content.strip() + "\n"
    buf = io.StringIO(content)
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(buf)
        except Exception as e:
            errors.append("%s: %s" % (cls.__name__, e))
            buf.seek(0)
    raise DeployError("无法解析私钥: " + " | ".join(errors))


def _connect(host, port, user, password=None, key_content=None):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host,
        port=port,
        username=user,
        password=password,
        timeout=15,
        allow_agent=False,
        look_for_keys=False,
    )
    if key_content:
        kwargs["pkey"] = _load_pkey(key_content)
    try:
        client.connect(**kwargs)
    except paramiko.AuthenticationException as e:
        client.close()
        raise DeployError("SSH 认证失败: %s" % e)
    except Exception as e:
        client.close()
        raise DeployError("SSH 连接失败: %s" % e)
    return client


def _run(client, command, timeout=30):
    out = err = ""
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
    except Exception as e:
        raise DeployError("命令执行失败[%s]: %s 部分输出<<%s>> 错误<<%s>>" %
                          (type(e).__name__, repr(e), out[:200], err[:200]))
    return code, out, err


def _shell_quote(text):
    return "'" + str(text).replace("'", "'\\''") + "'"


# ---------------------------------------------------------------------------
# 部署到 Linux
# ---------------------------------------------------------------------------

def _expand_install_path(client, install_path):
    """在远程把安装路径展开为绝对路径(解析 ~ 与 $HOME)。"""
    _, home_out, _ = _run(client, "printf '%s\\n' \"$HOME\"")
    home = home_out.strip() or "/root"
    p = (install_path or "~/.ssh/authorized_keys").strip() or "~/.ssh/authorized_keys"
    if p == "~":
        return home
    if p.startswith("~/"):
        return home + p[1:]
    if p.startswith("$HOME"):
        return home + p[len("$HOME"):]
    if p.startswith("/"):
        return p
    return home + "/" + p


def deploy_linux(host, port, user, public_key, password=None, key_content=None,
                 install_path="~/.ssh/authorized_keys"):
    pub = parse_pubkey(public_key)
    client = _connect(host, port, user, password, key_content)
    try:
        abs_path = _expand_install_path(client, install_path)
        q = _shell_quote(abs_path)
        remote = (
            "mkdir -p \"$(dirname {0})\" && chmod 700 \"$(dirname {0})\" && "
            "touch {0} && chmod 600 {0} && "
            "grep -qF {1} {0} 2>/dev/null || echo {1} >> {0}"
        ).format(q, _shell_quote(pub))
        code, out, err = _run(client, remote)
    finally:
        client.close()
    if code != 0:
        raise DeployError("Linux 部署失败(exit=%d): %s" % (code, (err or out).strip()))
    return {"ok": True, "output": out.strip(), "target": user + "@" + host}


# ---------------------------------------------------------------------------
# 部署到 RouterOS
# ---------------------------------------------------------------------------

def _ros_quote(text):
    """RouterOS 用双引号表示含空格的字符串, 转义 \\ 和 \"。"""
    text = str(text)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ros_version_major(version):
    """从 '7.15.2 (stable)' 中提取主版本号, 解析失败返回 None。"""
    import re
    m = re.search(r"(\d+)\.", version or "")
    return int(m.group(1)) if m else None


def deploy_routeros(host, port, user, public_key, password=None, key_content=None,
                    router_user=None):
    pub = parse_pubkey(public_key)
    target = router_user or user
    ktype = pub.split()[0]
    client = _connect(host, port, user, password, key_content)
    try:
        version = None
        vcode, vout, _ = _run(client, ':put [/system resource get version]')
        if vcode == 0 and vout.strip():
            version = vout.strip().splitlines()[-1].strip()
        code, out, err = 0, "", ""
        # RouterOS 7.x 用 key= 参数; 旧版本用 public-key= 参数, 依次尝试。
        for param in ("key", "public-key"):
            remote = "/user ssh-keys add user={0} {1}={2}".format(
                _ros_quote(target), param, _ros_quote(pub))
            print("[routeros] cmd: %s (version=%s)" % (remote, version), flush=True)
            code, out, err = _run(client, remote)
            if code == 0:
                break
    finally:
        client.close()
    if code != 0:
        errmsg = (err or out).strip()
        hint = ("。请确认该 RouterOS 支持 %s 类型公钥，以及用户名 %s 存在且允许 SSH 认证"
                % (ktype, target))
        raise DeployError("RouterOS 部署失败(exit=%d): %s%s" % (code, errmsg, hint))
    return {"ok": True, "output": out.strip(), "target": user + "@" + host, "ros_version": version}


def deploy_key(host, port, user, password, public_key, platform="linux", router_user=None,
               key_content=None):
    """接受端: 部署公钥。platform: linux | routeros, 认证用密码或私钥。"""
    platform = (platform or "linux").lower()
    if platform == "routeros":
        return deploy_routeros(host, port, user, public_key, password, key_content, router_user)
    if platform in ("linux", ""):
        return deploy_linux(host, port, user, public_key, password, key_content,
                            install_path="~/.ssh/authorized_keys")
    raise DeployError("不支持的接受端平台: %s" % platform)


# ---------------------------------------------------------------------------
# 在远端主机上生成私钥(发起端, Linux)
# ---------------------------------------------------------------------------

def generate_key_on_remote(host, port, user, password, key_type="ed25519"):
    """通过 SSH 登录目标主机, 在其 ~/.ssh 下生成密钥对, 返回公钥等信息。"""
    if key_type not in ("ed25519", "rsa"):
        raise DeployError("不支持的密钥类型: %s" % key_type)
    client = _connect(host, port, user, password)
    try:
        code, out, err = _run(client,
                              'mkdir -p ~/.ssh && chmod 700 ~/.ssh && printf "%s\\n" "$HOME"')
        if code != 0:
            raise DeployError("远程准备 .ssh 目录失败: %s" % (err or out))
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        home = lines[-1] if lines else None
        if not home or not home.startswith("/"):
            raise DeployError("无法确定远程 HOME 目录")
        key_path = home + "/.ssh/id_" + key_type
        pub_path = key_path + ".pub"
        remote = (
            'KP=%s; TS=$(date +%%s); '
            '[ -e "$KP" ] && mv "$KP" "$KP.bak.$TS"; '
            '[ -e "$KP.pub" ] && mv "$KP.pub" "$KP.pub.bak.$TS"; '
            'ssh-keygen -t %s -f "$KP" -N \'\' -C "$(whoami)@$(hostname)" </dev/null; '
            'echo "@@PUB@@"; cat "$KP.pub"; echo "@@PRIV@@"; cat "$KP"'
        ) % (_shell_quote(key_path), key_type)
        code, out, err = _run(client, remote)
        if code != 0:
            raise DeployError("远端生成密钥失败(exit=%d): %s" % (code, (err or out).strip()))
        pub_lines, priv_text = [], ""
        if "@@PUB@@" in out:
            rest = out.split("@@PUB@@", 1)[1]
            if "@@PRIV@@" in rest:
                pub_part, priv_part = rest.split("@@PRIV@@", 1)
                pub_lines = [ln for ln in pub_part.splitlines() if ln.strip()]
                priv_text = priv_part.strip()
        if not pub_lines:
            pub_lines = [ln for ln in out.splitlines() if ln.strip()]
        if not pub_lines:
            raise DeployError("未读取到生成的公钥")
        return {
            "ok": True,
            "public": pub_lines[-1].strip(),
            "priv_path": key_path,
            "pub_path": pub_path,
            "private": priv_text,
            "key_type": key_type,
        }
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 在 Windows 主机上生成私钥(发起端) —— 通过 PowerShell EncodedCommand 执行
# ---------------------------------------------------------------------------

def _run_pwsh(client, ps_script):
    """以 EncodedCommand 方式在 Windows 上执行 PowerShell 脚本(兼容 cmd 默认 shell)。"""
    b64 = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    return _run(client, "powershell -NoProfile -NonInteractive -EncodedCommand " + b64)


def _win_write_base64(client, remote_path, data_b64, chunk=2000):
    """把 base64 数据分块写入 Windows 文件(规避命令行长度上限)。

    每块拆成一条短 PowerShell 命令, 首块 WriteAllBytes, 之后 AppendAllBytes。
    """
    for i in range(0, len(data_b64), chunk):
        part = data_b64[i:i+chunk]
        mode = "WriteAllBytes" if i == 0 else "AppendAllBytes"
        ps = (
            "$p = '" + remote_path.replace("'", "''") + "'\n"
            "$b = [Convert]::FromBase64String('" + part + "')\n"
            "[IO.File]::" + mode + "($p, $b)"
        )
        code, out, err = _run_pwsh(client, ps)
        if code != 0:
            raise DeployError("Windows 写入密钥失败(exit=%d): %s" % (code, (err or out).strip()))


def generate_key_on_windows(host, port, user, password, key_type="ed25519"):
    """服务端生成密钥, 写入 Windows 的 %USERPROFILE%\\.ssh 目录。

    不调用远端 ssh-keygen(避免空口令参数/交互提示导致挂起); 也不用超长命令行
    (RSA 私钥 base64 后会把 Windows cmd 命令行撑爆)。优先走 SFTP(与默认 shell
    无关, 不会遇到 cmd 不识别 PowerShell 语法的问题); 无 SFTP 时用分块
    EncodedCommand PowerShell 命令兜底。
    """
    if key_type not in ("ed25519", "rsa"):
        raise DeployError("不支持的密钥类型: %s" % key_type)
    kp = generate_keypair(key_type, comment="ssh-web@windows")
    key_name = "id_" + key_type
    client = _connect(host, port, user, password)
    try:
        sftp = None
        try:
            sftp = client.open_sftp()
        except Exception:
            sftp = None

        if sftp is not None:
            try:
                home = sftp.normalize(".").rstrip("\\")
                ssh_dir = home + "\\.ssh"
                try:
                    sftp.mkdir(ssh_dir)
                except OSError:
                    pass
                priv_remote = ssh_dir + "\\" + key_name
                pub_remote = ssh_dir + "\\" + key_name + ".pub"
                ts = int(time.time())
                for rp in (priv_remote, pub_remote):
                    try:
                        sftp.stat(rp)
                        sftp.rename(rp, rp + ".bak." + str(ts))
                    except OSError:
                        pass
                with sftp.file(priv_remote, "w") as f:
                    f.write(kp["private"].encode("utf-8"))
                with sftp.file(pub_remote, "w") as f:
                    f.write(kp["public"].encode("utf-8"))
                with sftp.file(pub_remote, "r") as f:
                    pub = f.read().decode("utf-8", "replace")
            finally:
                sftp.close()
        else:
            ps_home = (
                '$d = Join-Path $env:USERPROFILE ".ssh"; '
                'New-Item -ItemType Directory -Force -Path $d | Out-Null; '
                'Write-Output $env:USERPROFILE'
            )
            code, out, err = _run_pwsh(client, ps_home)
            if code != 0:
                raise DeployError("无法确定 Windows 用户主目录: %s" % (err or out).strip())
            lines = [ln for ln in out.splitlines() if ln.strip()]
            if not lines:
                raise DeployError("无法确定 Windows 用户主目录")
            home = lines[-1].strip()
            ssh_dir = home.rstrip("\\") + "\\.ssh"
            priv_remote = ssh_dir + "\\" + key_name
            pub_remote = ssh_dir + "\\" + key_name + ".pub"
            _win_write_base64(client, priv_remote, base64.b64encode(kp["private"].encode("utf-8")).decode("ascii"))
            _win_write_base64(client, pub_remote, base64.b64encode(kp["public"].encode("utf-8")).decode("ascii"))
            code, out, err = _run_pwsh(client, "Get-Content '" + pub_remote.replace("'", "''") + "'")
            if code != 0:
                raise DeployError("读取 Windows 公钥失败: %s" % (err or out).strip())
            pub = out
    finally:
        client.close()
    lines = [ln for ln in pub.splitlines() if ln.strip()]
    if not lines:
        raise DeployError("未读取到 Windows 上的公钥")
    return {
        "ok": True,
        "public": lines[-1].strip(),
        "priv_path": "%USERPROFILE%\\.ssh\\" + key_name,
        "pub_path": "%USERPROFILE%\\.ssh\\" + key_name + ".pub",
        "private": kp["private"],
        "key_type": key_type,
    }


# ---------------------------------------------------------------------------
# 按平台分发: 发起端
# ---------------------------------------------------------------------------

def generate_key(host, port, user, password, platform="linux", key_type="ed25519"):
    """发起端: 在远端主机生成私钥。platform: linux | windows"""
    platform = (platform or "linux").lower()
    if platform == "windows":
        return generate_key_on_windows(host, port, user, password, key_type)
    if platform in ("linux", ""):
        return generate_key_on_remote(host, port, user, password, key_type)
    raise DeployError("不支持的发起端平台: %s" % platform)
