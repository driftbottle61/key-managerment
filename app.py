# -*- coding: utf-8 -*-
"""ssh-web: 网页版 SSH 私钥生成与公钥部署工具(Flask)。"""
import os
import json
import secrets
import time
from functools import wraps

from flask import (Flask, jsonify, render_template, request, redirect, url_for,
                   session, abort)

from core import generate_key, deploy_key, DeployError

import keystore

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("SSHWEB_CONFIG") or (os.path.join("/app/data", "config.json") if os.path.isdir("/app/data") else os.path.join(BASE_DIR, "config.json"))

app = Flask(__name__)


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

def hash_password(pw):
    from werkzeug.security import generate_password_hash
    return generate_password_hash(pw)


def check_password(hashval, pw):
    from werkzeug.security import check_password_hash
    try:
        return check_password_hash(hashval, pw)
    except Exception:
        return False


def load_config():
    cfg = {
        "secret_key": secrets.token_hex(32),
        "admin_user": "admin",
        "admin_password_hash": None,
        "key_ttl_minutes": 60,
        "login_max_fail": 5,
        "login_lock_seconds": 300,
    }
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def ensure_config():
    cfg = load_config()
    changed = False
    if not cfg.get("secret_key") or cfg["secret_key"] == "CHANGE_ME":
        cfg["secret_key"] = secrets.token_hex(32)
        changed = True
    if not cfg.get("admin_password_hash"):
        user = os.environ.get("SSHWEB_ADMIN_USER", "admin")
        pw = os.environ.get("SSHWEB_ADMIN_PASSWORD")
        if not pw:
            pw = secrets.token_urlsafe(12)
            with open(os.path.join(BASE_DIR, "INITIAL_PASSWORD.txt"), "w", encoding="utf-8") as f:
                f.write("初始登录密码(请登录后修改或删除本文件):\n%s\n" % pw)
            print("[!] 已生成初始密码, 见 INITIAL_PASSWORD.txt", flush=True)
        cfg["admin_user"] = user
        cfg["admin_password_hash"] = hash_password(pw)
        changed = True
    if changed:
        save_config(cfg)
    app.config["SECRET_KEY"] = cfg["secret_key"]
    return cfg


CONFIG = ensure_config()
app.config["SECRET_KEY"] = CONFIG["secret_key"]
LOGIN_MAX_FAIL = CONFIG.get("login_max_fail", 5)
LOGIN_LOCK_SECONDS = CONFIG.get("login_lock_seconds", 300)


# ---------------------------------------------------------------------------
# 登录 / 鉴权 / CSRF
# ---------------------------------------------------------------------------

def get_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(24)
    return session["csrf"]


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def csrf_protect(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method == "POST":
            token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            if not token or token != session.get("csrf"):
                abort(400, description="CSRF 校验失败")
        return f(*args, **kwargs)
    return wrapper


@app.context_processor
def inject_csrf():
    return {"csrf_token": get_csrf()}


@app.errorhandler(400)
def bad_request(e):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": str(e.description)}), 400
    return str(e.description), 400


@app.before_request
def _log_request():
    print("[req] %s %s from %s" % (request.method, request.path, request.remote_addr), flush=True)


@app.errorhandler(DeployError)
def deploy_error(e):
    return jsonify({"ok": False, "error": str(e)}), 200


# ---------------------------------------------------------------------------
# 登录 / 登出
# ---------------------------------------------------------------------------

login_state = {}   # ip -> {"fail": int, "locked_until": float}


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("index"))
    ip = request.remote_addr or "?"
    state = login_state.setdefault(ip, {"fail": 0, "locked_until": 0})
    if time.time() < state["locked_until"]:
        return render_template("login.html", error="登录失败次数过多, 请稍后再试",
                               csrf_token=get_csrf()), 429

    if request.method == "POST":
        if not csrf_ok(request):
            return render_template("login.html", error="会话过期, 请刷新后重试",
                                   csrf_token=get_csrf()), 400
        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        if user == CONFIG["admin_user"] and check_password(CONFIG["admin_password_hash"], pw):
            session.clear()
            session["logged_in"] = True
            session["csrf"] = secrets.token_hex(24)
            login_state[ip] = {"fail": 0, "locked_until": 0}
            nxt = request.args.get("next") or url_for("index")
            return redirect(nxt)
        state["fail"] += 1
        if state["fail"] >= LOGIN_MAX_FAIL:
            state["locked_until"] = time.time() + LOGIN_LOCK_SECONDS
            state["fail"] = 0
            return render_template("login.html", error="失败次数过多, 已锁定 %d 秒"
                                   % LOGIN_LOCK_SECONDS, csrf_token=get_csrf()), 429
        return render_template("login.html", error="用户名或密码错误(剩余 %d 次)"
                               % (LOGIN_MAX_FAIL - state["fail"]), csrf_token=get_csrf()), 401
    return render_template("login.html", csrf_token=get_csrf())


def csrf_ok(request):
    token = request.form.get("csrf_token")
    return bool(token and token == session.get("csrf"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# 页面
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/password")
@login_required
def password_page():
    return render_template("password.html")


@app.route("/health")
def health():
    return jsonify({"ok": True, "time": int(time.time())})


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# API: 发起端生成私钥
# ---------------------------------------------------------------------------

@app.route("/api/gen-remote", methods=["POST"])
@login_required
@csrf_protect
def api_gen_remote():
    data = request.get_json(silent=True) or {}
    host = (data.get("host") or "").strip()
    port = int(data.get("port") or 22)
    user = (data.get("user") or "").strip()
    password = data.get("password") or None
    key_type = data.get("key_type") or "ed25519"
    platform = data.get("platform") or "linux"
    if not host or not user:
        return jsonify({"ok": False, "error": "缺少主机地址或用户名"}), 400
    if not password:
        return jsonify({"ok": False, "error": "请提供 SSH 密码"}), 400
    print("[gen-remote] %s:%s user=%s platform=%s keytype=%s" % (host, port, user, platform, key_type), flush=True)
    try:
        result = generate_key(host, port, user, password, platform, key_type)
        print("[gen-remote] OK public=%s" % result["public"].split()[1][:16], flush=True)
    except DeployError as e:
        print("[gen-remote] FAIL: %s" % e, flush=True)
        return jsonify({"ok": False, "error": str(e)}), 200
    # 记住公钥, 供接受端部署时使用
    session["last_pubkey"] = result["public"]
    # 保存到密钥库, 供"历史私钥"下拉选择/重新部署
    had_key = "keystore_key" in CONFIG
    try:
        rec = keystore.add_record(CONFIG, {
            "src_platform": platform,
            "src_host": host,
            "src_port": port,
            "src_user": user,
            "key_type": key_type,
            "priv_path": result.get("priv_path", ""),
            "pub_path": result.get("pub_path", ""),
        }, result.get("public", ""), result.get("private", ""))
        if not had_key:
            save_config(CONFIG)
        result["keystore_id"] = rec["id"]
    except Exception as e:
        print("[keystore] 保存失败: %s" % e, flush=True)
    return jsonify(result)


# ---------------------------------------------------------------------------
# API: 接受端部署公钥
# ---------------------------------------------------------------------------

@app.route("/api/deploy-remote", methods=["POST"])
@login_required
@csrf_protect
def api_deploy_remote():
    data = request.get_json(silent=True) or {}
    host = (data.get("host") or "").strip()
    port = int(data.get("port") or 22)
    user = (data.get("user") or "").strip()
    password = data.get("password") or None
    key_content = data.get("auth_key") or None
    public_key = (data.get("public_key") or "").strip() or session.get("last_pubkey", "")
    platform = data.get("platform") or "linux"
    router_user = data.get("router_user") or user
    if not host or not user:
        return jsonify({"ok": False, "error": "缺少主机地址或用户名"}), 400
    if not password and not key_content:
        return jsonify({"ok": False, "error": "请提供 SSH 密码或私钥"}), 400
    if not public_key:
        return jsonify({"ok": False, "error": "公钥为空, 请先在发起端生成私钥或手动粘贴公钥"}), 400
    try:
        result = deploy_key(host, port, user, password, public_key, platform, router_user, key_content)
    except DeployError as e:
        return jsonify({"ok": False, "error": str(e)}), 200
    return jsonify(result)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# API: 密钥库(历史私钥)
# ---------------------------------------------------------------------------

@app.route("/api/keystore/list", methods=["GET"])
@login_required
def api_keystore_list():
    return jsonify({"ok": True, "records": keystore.list_records()})


@app.route("/api/keystore/get", methods=["GET"])
@login_required
def api_keystore_get():
    rec_id = request.args.get("id") or ""
    rec = keystore.get_record(CONFIG, rec_id)
    if not rec:
        return jsonify({"ok": False, "error": "未找到该密钥"}), 404
    return jsonify({"ok": True, "record": rec})


@app.route("/api/keystore/delete", methods=["POST"])
@login_required
@csrf_protect
def api_keystore_delete():
    data = request.get_json(silent=True) or {}
    keystore.delete_record(data.get("id") or "")
    return jsonify({"ok": True})


@app.route("/api/change-password", methods=["POST"])
@login_required
@csrf_protect
def api_change_password():
    data = request.get_json(silent=True) or {}
    old_pw = data.get("old_password") or ""
    new_pw = data.get("new_password") or ""
    if not check_password(CONFIG.get("admin_password_hash"), old_pw):
        return jsonify({"ok": False, "error": "当前密码不正确"}), 200
    if len(new_pw) < 6:
        return jsonify({"ok": False, "error": "新密码至少 6 位"}), 200
    if new_pw == old_pw:
        return jsonify({"ok": False, "error": "新密码不能与当前密码相同"}), 200
    CONFIG["admin_password_hash"] = hash_password(new_pw)
    save_config(CONFIG)
    try:
        ipf = os.path.join(BASE_DIR, "INITIAL_PASSWORD.txt")
        if os.path.exists(ipf):
            os.remove(ipf)
    except OSError:
        pass
    return jsonify({"ok": True, "message": "密码修改成功"})


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------

def main():
    host = os.environ.get("SSHWEB_HOST", "0.0.0.0")
    port = int(os.environ.get("SSHWEB_PORT", 8080))
    print("[*] ssh-web 启动于 http://%s:%d  用户: %s" % (host, port, CONFIG["admin_user"]), flush=True)
    try:
        from waitress import serve
        serve(app, host=host, port=port, threads=8)
    except ImportError:
        app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":
    main()
