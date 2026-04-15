"""
MindVault 许可证服务器
部署到云端（Railway / Render / 任意 VPS）

环境变量：
  ADMIN_SECRET   管理员密钥（生成许可证时需要）
  DATABASE_URL   可选，默认使用本地 SQLite
"""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="MindVault License Server", docs_url=None)  # 关闭文档页面

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 配置 ────────────────────────────────────────────────────────────────────────
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change-this-in-production-!!!!")
DB_PATH      = Path(os.environ.get("DB_PATH", "licences.db"))


# ── 数据库 ───────────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licences (
            key         TEXT PRIMARY KEY,
            mac_hash    TEXT,              -- 绑定的 MAC 地址哈希（未激活时为 NULL）
            status      TEXT DEFAULT 'active',  -- active / revoked
            note        TEXT DEFAULT '',   -- 备注（如：客户名称）
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            activated_at TEXT,             -- 首次激活时间
            last_seen   TEXT               -- 最近一次验证时间
        )
    """)
    conn.commit()
    conn.close()


init_db()


# ── 工具函数 ─────────────────────────────────────────────────────────────────────

def hash_mac(mac: str) -> str:
    """对 MAC 地址做单向哈希，服务器不存储原始 MAC。"""
    return hashlib.sha256(mac.lower().strip().encode()).hexdigest()


def generate_key() -> str:
    """生成格式为 XXXX-XXXX-XXXX-XXXX 的许可证密钥。"""
    raw = secrets.token_hex(8).upper()
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"


def verify_admin(secret: str):
    if not hmac.compare_digest(secret, ADMIN_SECRET):
        raise HTTPException(403, "Invalid admin secret")


# ── 管理员接口（生成、撤销、查询许可证）──────────────────────────────────────────

class CreateRequest(BaseModel):
    count: int = 1       # 批量生成数量
    note: str  = ""      # 备注（客户名称等）


@app.post("/admin/create")
def admin_create(req: CreateRequest, x_admin_secret: str = Header(...)):
    verify_admin(x_admin_secret)
    if req.count < 1 or req.count > 100:
        raise HTTPException(400, "count must be 1~100")

    conn = get_db()
    keys = []
    for _ in range(req.count):
        key = generate_key()
        conn.execute(
            "INSERT INTO licences (key, note) VALUES (?, ?)",
            (key, req.note)
        )
        keys.append(key)
    conn.commit()
    conn.close()
    return {"keys": keys, "count": len(keys)}


@app.get("/admin/list")
def admin_list(x_admin_secret: str = Header(...)):
    verify_admin(x_admin_secret)
    conn = get_db()
    rows = conn.execute(
        "SELECT key, mac_hash, status, note, created_at, activated_at, last_seen "
        "FROM licences ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return {"licences": [dict(r) for r in rows]}


@app.post("/admin/revoke/{key}")
def admin_revoke(key: str, x_admin_secret: str = Header(...)):
    """撤销许可证（例如退款后禁用）。"""
    verify_admin(x_admin_secret)
    conn = get_db()
    r = conn.execute(
        "UPDATE licences SET status='revoked' WHERE key=?", (key,)
    )
    conn.commit()
    conn.close()
    if r.rowcount == 0:
        raise HTTPException(404, "Key not found")
    return {"message": f"Key {key} revoked"}


@app.post("/admin/unbind/{key}")
def admin_unbind(key: str, x_admin_secret: str = Header(...)):
    """解绑 MAC（如用户更换电脑时使用）。"""
    verify_admin(x_admin_secret)
    conn = get_db()
    r = conn.execute(
        "UPDATE licences SET mac_hash=NULL, activated_at=NULL WHERE key=? AND status='active'",
        (key,)
    )
    conn.commit()
    conn.close()
    if r.rowcount == 0:
        raise HTTPException(404, "Key not found or already revoked")
    return {"message": f"Key {key} unbound, can be activated on a new machine"}


# ── 客户端接口（激活、验证）──────────────────────────────────────────────────────

class ActivateRequest(BaseModel):
    key:     str   # 许可证密钥
    mac:     str   # 客户端 MAC 地址（明文，服务器做哈希后存储）
    version: str = "1.0.0"


class VerifyRequest(BaseModel):
    key: str
    mac: str


@app.post("/activate")
def activate(req: ActivateRequest):
    """
    激活许可证：
    - 未绑定：绑定到当前 MAC，返回成功
    - 已绑定同一 MAC：幂等，返回成功（允许重装系统后重新激活）
    - 已绑定不同 MAC：返回失败
    - 已撤销：返回失败
    """
    key      = req.key.upper().strip()
    mac_hash = hash_mac(req.mac)

    conn = get_db()
    row = conn.execute(
        "SELECT mac_hash, status FROM licences WHERE key=?", (key,)
    ).fetchone()

    if not row:
        conn.close()
        return {"ok": False, "reason": "INVALID_KEY", "message": "许可证无效"}

    if row["status"] == "revoked":
        conn.close()
        return {"ok": False, "reason": "REVOKED", "message": "许可证已被撤销"}

    now = datetime.now().isoformat()

    if row["mac_hash"] is None:
        # 首次激活：绑定 MAC
        conn.execute(
            "UPDATE licences SET mac_hash=?, activated_at=?, last_seen=? WHERE key=?",
            (mac_hash, now, now, key)
        )
        conn.commit()
        conn.close()
        return {"ok": True, "message": "激活成功"}

    if row["mac_hash"] == mac_hash:
        # 同一台机器重新激活（重装系统等场景），允许
        conn.execute(
            "UPDATE licences SET last_seen=? WHERE key=?", (now, key)
        )
        conn.commit()
        conn.close()
        return {"ok": True, "message": "激活成功（已绑定）"}

    # 不同 MAC，拒绝
    conn.close()
    return {
        "ok": False,
        "reason": "MAC_MISMATCH",
        "message": "此许可证已在另一台计算机上激活。如需换机，请联系支持。"
    }


@app.post("/verify")
def verify(req: VerifyRequest):
    """
    验证许可证（软件每次启动时调用）。
    返回简单的 ok/not-ok，不暴露内部原因（防止逆向工程）。
    """
    key      = req.key.upper().strip()
    mac_hash = hash_mac(req.mac)

    conn = get_db()
    row = conn.execute(
        "SELECT mac_hash, status FROM licences WHERE key=?", (key,)
    ).fetchone()
    conn.close()

    if not row or row["status"] != "active" or row["mac_hash"] != mac_hash:
        return {"ok": False}

    # 更新最近验证时间（异步写，不阻塞响应）
    import threading
    def update_seen():
        c = get_db()
        c.execute("UPDATE licences SET last_seen=? WHERE key=?",
                  (datetime.now().isoformat(), key))
        c.commit(); c.close()
    threading.Thread(target=update_seen, daemon=True).start()

    return {"ok": True}


@app.get("/health")
def health():
    return {"status": "ok"}
