import os
import asyncio
import sqlite3
import json
import socket
import logging
import hmac
import hashlib
import time
import secrets
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Set, Tuple

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    Request,
    HTTPException,
    Query
)
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse
)
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import parse_qs
from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field

# ================== Настройки ==================

class Settings(BaseSettings):
    SHARED_SECRET: str = Field("rpcs_dev_secret_change_me", env="SHARED_SECRET")
    VIEWER_TOKEN: str = Field("view_dev_token", env="VIEWER_TOKEN")

    # Проверка метки времени (сек). Если <0 — не проверяем.
    AUTH_TS_SKEW: int = Field(-1, env="AUTH_TS_SKEW")

    # TTL для nonce (anti-replay)
    NONCE_TTL: int = Field(180, env="NONCE_TTL")

    # Разрешить агентов с публичных IP
    ALLOW_PUBLIC_AGENTS: bool = Field(True, env="ALLOW_PUBLIC_AGENTS")

    # Интервалы/таймауты
    HEARTBEAT_INTERVAL: int = 15          # (пока справочно)
    AGENT_STALE_SECONDS: int = 60         # по истечении удаляем (GC)

    # Ограничения размера сообщений
    MAX_TEXT_SIZE: int = 512_000
    MAX_VIEWER_TEXT_SIZE: int = 128_000

    # Логирование
    LOG_LEVEL: str = Field("INFO", env="LOG_LEVEL")

    # CORS (через запятую)
    CORS_ORIGINS: str = Field("*", env="CORS_ORIGINS")

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

# ================== Пути / директории ==================

APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web"
DB_PATH = APP_DIR / "server.sqlite3"

ALLOWED_FILE_TYPES = {
 "file_drives","file_list_adv","file_mkdir","file_rename","file_delete",
 "file_paste","file_zip_download","file_preview","file_search"
}
RESULT_FILE_TYPES = {
 "file_drives_result","file_list_adv_result","file_mkdir_result",
 "file_rename_result","file_delete_result","file_error",
 "file_paste_result","file_preview_result","file_search_result",
 "file_download_meta","file_download_chunk","file_download_end",
 "file_upload_done"
}

# ================== Логирование ==================

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logger = logging.getLogger("rpc-server")

# ================== Приложение ==================

app = FastAPI(title="Remote PC Control (Stream)")
# CORS
cors_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",")] if settings.CORS_ORIGINS != "*" else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

# ================== Реестры соединений ==================

active_agents: Dict[str, Dict[str, Any]] = {}   # agent_id -> {"ws": WebSocket, "info": dict, "since": str, "last_seen_ts": float}
viewers: Dict[str, Set[WebSocket]] = {}         # agent_id -> set(viewer WebSocket)

# ================== Анти-replay nonce ==================

_auth_nonces: Dict[str, float] = {}  # nonce -> ts

def _parse_last_seen(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").timestamp()
    except Exception:
        return 0.0


def db_cleanup_duplicates() -> None:
    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.cursor()
        cur.execute("SELECT id, hostname, last_seen FROM agents")
        rows = cur.fetchall()
        best: Dict[str, Tuple[str, float]] = {}
        to_delete: List[str] = []
        for agent_id, host, last_seen in rows:
            key = (host or "").strip().lower() or agent_id
            ts = _parse_last_seen(last_seen)
            current = best.get(key)
            if current is None:
                best[key] = (agent_id, ts)
                continue
            if ts > current[1]:
                to_delete.append(current[0])
                best[key] = (agent_id, ts)
            else:
                to_delete.append(agent_id)
        if to_delete:
            cur.executemany("DELETE FROM agents WHERE id=?", [(aid,) for aid in to_delete])
        con.commit()
    finally:
        con.close()


def db_upsert_agent(agent_id: str, hostname: str, info: Dict[str, Any]):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.cursor()
        cur.execute("""
            INSERT INTO agents(id, hostname, group_id, last_seen, info_json)
            VALUES(?, ?, NULL, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                hostname=excluded.hostname,
                last_seen=excluded.last_seen,
                info_json=excluded.info_json
        """, (agent_id, hostname, now, json.dumps(info, ensure_ascii=False)))
        if hostname:
            cur.execute(
                """
                DELETE FROM agents
                WHERE LOWER(COALESCE(hostname,'')) = LOWER(?)
                  AND id <> ?
                """,
                (hostname, agent_id),
            )
        con.commit()
    finally:
        con.close()
    if hostname:
        db_cleanup_duplicates()

def _auth_cleanup():
    """Удаляет протухшие nonce."""
    now = time.time()
    ttl = settings.NONCE_TTL
    for n, nts in list(_auth_nonces.items()):
        if now - nts > ttl:
            _auth_nonces.pop(n, None)


def _auth_verify_hello_ex(hello: Dict[str, Any]) -> Tuple[bool, str]:
    """Расширенная проверка сообщения HELLO от агента."""
    try:
        auth = hello.get("auth") or {}
        agent_id = str(hello.get("agent_id") or "")
        if not agent_id:
            return False, "no_agent_id"

        try:
            ts = int(auth.get("ts") or 0)
        except Exception:
            ts = 0
        nonce = str(auth.get("nonce") or "")
        sig = str(auth.get("sig") or "")

        if not (nonce and sig):
            return False, "no_nonce_or_sig"

        # Проверка времени
        if settings.AUTH_TS_SKEW >= 0 and abs(int(time.time()) - ts) > settings.AUTH_TS_SKEW:
            return False, "ts_skew"

        # Anti replay
        _auth_cleanup()
        if nonce in _auth_nonces:
            return False, "replay_nonce"

        msg = f"{agent_id}|{ts}|{nonce}".encode("utf-8")
        expect = hmac.new(settings.SHARED_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            return False, "bad_sig"

        _auth_nonces[nonce] = time.time()
        return True, "ok"
    except Exception as e:
        return False, f"error:{e}"


# ================== IP фильтрация ==================

PRIVATE_NETS = [ipaddress.ip_network(x) for x in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _ip_in_private(peer: str) -> bool:
    try:
        ip = ipaddress.ip_address(peer)
        return any(ip in net for net in PRIVATE_NETS)
    except Exception:
        return False


# ================== БД (SQLite) ==================

def db_init():
    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL)")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                hostname TEXT,
                group_id INTEGER,
                last_seen TEXT,
                info_json TEXT,
                FOREIGN KEY(group_id) REFERENCES groups(id)
            )
        """)
        con.commit()
    finally:
        con.close()


def db_list_agents() -> List[Dict[str, Any]]:
    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.cursor()
        cur.execute("""SELECT a.id, a.hostname, a.group_id, a.last_seen, a.info_json, g.name
                       FROM agents a LEFT JOIN groups g ON a.group_id=g.id ORDER BY a.hostname""")
        rows = cur.fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            aid, host, gid, last_seen, info_json, gname = r
            try:
                info = json.loads(info_json) if info_json else {}
            except Exception:
                info = {}
            out.append({
                "agent_id": aid,
                "hostname": host,
                "group_id": gid,
                "group_name": gname,
                "last_seen": last_seen,
                "info": info
            })
        return out
    finally:
        con.close()


def db_list_groups():
    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.cursor()
        cur.execute("SELECT id, name FROM groups ORDER BY name")
        return [{"id": r[0], "name": r[1]} for r in cur.fetchall()]
    finally:
        con.close()


def db_create_group(name: str):
    if not name.strip():
        raise HTTPException(400, "empty name")
    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.cursor()
        cur.execute("INSERT INTO groups(name) VALUES(?)", (name.strip(),))
        con.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "duplicate")
    finally:
        con.close()


def db_assign_group(agent_id: str, group_id: int | None):
    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.cursor()
        cur.execute("UPDATE agents SET group_id=? WHERE id=?", (group_id, agent_id))
        con.commit()
    finally:
        con.close()


# ================== Фоновый GC ==================

async def _gc_agents_loop():
    """Удаляет «зависших» агентов без активности."""
    while True:
        try:
            now = time.time()
            stale: List[str] = []
            for aid, meta in list(active_agents.items()):
                last = meta.get("last_seen_ts") or 0
                if now - last > settings.AGENT_STALE_SECONDS:
                    stale.append(aid)
            for aid in stale:
                active_agents.pop(aid, None)
                viewers.pop(aid, None)
                logger.info("GC: удалён неактивный агент %s", aid)
        except Exception as e:
            logger.exception("GC error: %s", e)
        await asyncio.sleep(10)


# ================== Startup / Shutdown ==================

@app.on_event("startup")
def _startup():
    WEB_DIR.mkdir(parents=True, exist_ok=True)
    db_init()
    db_cleanup_duplicates()
    if not hasattr(app.state, "gc_task"):
        app.state.gc_task = asyncio.create_task(_gc_agents_loop())
    logger.info("Startup complete")


@app.on_event("shutdown")
def _shutdown():
    task = getattr(app.state, "gc_task", None)
    if task:
        task.cancel()
    logger.info("Shutdown complete")


# ================== HTTP Маршруты ==================

@app.get("/", response_class=HTMLResponse)
def index():
    index_file = WEB_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>Remote PC Control</h1><p>No index.html</p>")
    return HTMLResponse(index_file.read_text(encoding="utf-8"))


@app.get("/view/{agent_id}", response_class=HTMLResponse)
def view_agent(agent_id: str):
    tmpl = WEB_DIR / "view.html"
    if not tmpl.exists():
        return HTMLResponse(f"<h1>Viewer</h1><p>No template. agent_id={agent_id}</p>")
    html = tmpl.read_text(encoding="utf-8")
    return HTMLResponse(html.replace("{{AGENT_ID}}", agent_id))


@app.get("/api/agents")
def api_agents():
    items = db_list_agents()
    for it in items:
        it["online"] = it["agent_id"] in active_agents
    return {"agents": items}


@app.get("/api/groups")
def api_groups():
    return {"groups": db_list_groups()}


@app.post("/api/groups")
async def api_groups_create(req: Request):
    data = await req.json()
    db_create_group(data.get("name", ""))
    return {"status": "ok"}


@app.post("/api/agents/{agent_id}/assign_group")
async def api_agent_assign(agent_id: str, req: Request):
    data = await req.json()
    db_assign_group(agent_id, data.get("group_id"))
    return {"status": "ok"}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    return {"status": "ok", "agents_online": len(active_agents)}


@app.get("/bootstrap.ps1")
def bootstrap_ps1(
    request: Request,
    host: str | None = Query(default=None, description="IP или хост сервера"),
    port: int | None = Query(default=None, description="Порт сервера, по умолчанию 8765"),
    insecure: int | None = Query(default=None, description="1 — не проверять TLS (dev)")
):
    # Определяем host
    req_host = host or (request.headers.get("host") or "")
    if ":" in req_host:
        h, _, p = req_host.rpartition(":")
        if h.startswith("[") and h.endswith("]"):
            h = h[1:-1]
        req_host = h
        if not port:
            try:
                port = int(p)
            except Exception:
                pass
    if not req_host:
        try:
            req_host = socket.gethostbyname(socket.gethostname())
        except Exception:
            req_host = "127.0.0.1"

    if not port:
        try:
            port = int(str(request.url.port or "8765"))
        except Exception:
            port = 8765

    ssl_on = bool(os.environ.get("SSL_CERTFILE") and os.environ.get("SSL_KEYFILE"))
    http_scheme = "https" if ssl_on else "http"
    ws_scheme = "wss" if ssl_on else "ws"

    ws_uri = f"{ws_scheme}://{req_host}:{port}/ws/agent"
    download_url = f"{http_scheme}://{req_host}:{port}/static/agent/rpc-agent.exe"
    secret = settings.SHARED_SECRET
    tls_insecure = insecure if insecure is not None else (1 if ssl_on else 0)

    ps = f"""$ErrorActionPreference = "Stop"
$dir = Join-Path $env:LOCALAPPDATA "RPC-Agent"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir "rpc-agent.exe"

Write-Host "Скачиваю агента..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "{download_url}" -OutFile $exe

Write-Host "Настраиваю переменные окружения..." -ForegroundColor Cyan
setx SHARED_SECRET "{secret}" | Out-Null
setx AGENT_SERVER "ws://localhost:8765/ws/agent" | Out-Null
{"setx AGENT_TLS_INSECURE \"1\" | Out-Null" if tls_insecure else ""}

Write-Host "Запускаю агента..." -ForegroundColor Cyan
Start-Process -FilePath $exe
Write-Host "Готово. Агент подключится к ws://localhost:8765/ws/agent" -ForegroundColor Green
"""
    return PlainTextResponse(ps, media_type="text/plain; charset=utf-8")

# в setx AGENT_SERVER "сюда вставить {ws_uri}" | Out-Null
# и тут Write-Host "Готово. Агент подключится к {ws_uri}." -ForegroundColor Green
# ================== WebSocket: АГЕНТ ==================

@app.websocket("/ws/agent")
async def ws_agent(ws: WebSocket):
    hostname = ""
    try:
        peer = ws.client.host if ws.client else ""
        if (not settings.ALLOW_PUBLIC_AGENTS) and peer and not _ip_in_private(peer):
            await ws.close(code=1008)
            return
    except Exception:
        peer = "?"

    await ws.accept()
    agent_id = None
    try:
        # Первое сообщение — HELLO (JSON)
        hello = await ws.receive_json()
        ok, reason = _auth_verify_hello_ex(hello)
        if not ok:
            logger.warning("AUTH FAIL peer=%s agent=%s reason=%s",
                           peer, str(hello.get("agent_id") or ""), reason)
            try:
                await ws.send_text(f"ERR_AUTH:{reason}")
            except Exception:
                pass
            await ws.close(code=1008)
            return

        agent_id = str(hello.get("agent_id") or "").strip()
        hostname = str(hello.get("host") or "").strip()
        if not agent_id:
            logger.warning("HELLO ERR empty agent_id peer=%s", peer)
            await ws.send_text("ERR")
            await ws.close(code=1008)
            return

        # БД (не роняем при ошибках)
        try:
            db_upsert_agent(agent_id, hostname, hello)
        except Exception as e:
            logger.exception("db_upsert_agent (handshake) failed: %s", e)

        active_agents[agent_id] = {
            "ws": ws,
            "info": hello,
            "since": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen_ts": time.time()
        }
        viewers.setdefault(agent_id, set())
        await ws.send_text("OK")
        logger.info("AGENT ONLINE %s (%s) from %s", agent_id, hostname, peer)

        # Основной цикл
        while True:
            message = await ws.receive()
            mtype = message.get("type")
            if mtype == "websocket.disconnect":
                break

            updated = False
            # Бинарные данные (например, кадры)
            if "bytes" in message and message["bytes"] is not None:
                frame = message["bytes"]
                updated = True
                dead: List[WebSocket] = []
                for vw in list(viewers.get(agent_id, set())):
                    try:
                        await vw.send_bytes(frame)
                    except Exception:
                        dead.append(vw)
                for d in dead:
                    viewers.get(agent_id, set()).discard(d)

            # Текстовые данные (команды / json / HB)
            elif "text" in message and message["text"] is not None:
                txt = message["text"]
                if txt == "HB":
                    # heartbeat от агента
                    active_agents[agent_id]["last_seen_ts"] = time.time()
                    continue
                if len(txt) > settings.MAX_TEXT_SIZE:
                    continue
                updated = True
                dead: List[WebSocket] = []
                for vw in list(viewers.get(agent_id, set())):
                    try:
                        await vw.send_text(txt)
                    except Exception:
                        dead.append(vw)
                for d in dead:
                    viewers.get(agent_id, set()).discard(d)

            if updated:
                active_agents[agent_id]["last_seen_ts"] = time.time()
                # Обновляем last_seen в БД
                try:
                    db_upsert_agent(agent_id, hostname, hello)
                except Exception as e:
                    logger.exception("db_upsert_agent (loop) failed: %s", e)

    except WebSocketDisconnect:
        logger.info("WS disconnect peer=%s agent=%s", peer, agent_id or "?")
    except Exception as e:
        logger.exception("WS agent error: %s", e)
        try:
            await ws.close()
        except Exception:
            pass
    finally:
        if agent_id:
            meta = active_agents.pop(agent_id, None)
            if meta:
                try:
                    payload = meta.get("info") or {}
                    db_upsert_agent(agent_id, payload.get("host") or hostname or "", payload)
                except Exception as e:
                    logger.exception("db_upsert_agent (disconnect) failed: %s", e)
            viewers.pop(agent_id, None)
            logger.info("AGENT OFFLINE %s", agent_id)


async def broadcast_to_viewers(aid: str, payload):
    """Рассылает payload всем viewer'ам агента."""
    vs = viewers.get(aid, set())
    dead = []
    txt = None
    if isinstance(payload, (dict, list)):
        try:
            txt = json.dumps(payload, ensure_ascii=False)
        except Exception:
            txt = str(payload)
    else:
        txt = str(payload)
    for vw in list(vs):
        try:
            await vw.send_text(txt)
        except Exception:
            dead.append(vw)
    for d in dead:
        vs.discard(d)

# ================== WebSocket: VIEWER ==================

@app.websocket("/ws/view/{agent_id}")
async def ws_view(ws: WebSocket, agent_id: str):
    qp = parse_qs(ws.url.query or "")
    token = (qp.get("token") or [""])[0]
    if token != settings.VIEWER_TOKEN:
        await ws.close(code=1008)
        return

    await ws.accept()
    viewers.setdefault(agent_id, set()).add(ws)
    try:
        while True:
            raw = await ws.receive_text()
            if raw == "HB":
                continue
            if len(raw) > settings.MAX_VIEWER_TEXT_SIZE:
                continue

            data = None
            try:
                data = json.loads(raw)
            except Exception:
                pass

            ag_meta = active_agents.get(agent_id) or {}
            agent_ws: WebSocket | None = ag_meta.get("ws")

            if data and isinstance(data, dict):
                mtype = data.get("type")
                # все команды продвинутого файлового менеджера
                if mtype in ALLOWED_FILE_TYPES:
                    if agent_ws:
                        await agent_ws.send_json(data)
                    continue
                # остальное транзитом
                if agent_ws:
                    await agent_ws.send_text(raw)
            else:
                if agent_ws:
                    await agent_ws.send_text(raw)
    except WebSocketDisconnect:
        pass
    finally:
        viewers.get(agent_id, set()).discard(ws)

# ================== Глобальный обработчик ошибок ==================

@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    logger.exception("Unhandled: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "internal_error"})

@app.get("/offline", response_class=HTMLResponse)
def offline():
    page = WEB_DIR / "offline.html"
    if not page.exists():
        return HTMLResponse("<h1>Offline</h1><p>No offline.html</p>")
    return HTMLResponse(page.read_text(encoding="utf-8"))

# ================== Точка входа ==================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8765"))
    cert = os.environ.get("SSL_CERTFILE") or None
    key = os.environ.get("SSL_KEYFILE") or None
    logger.info("Starting uvicorn on 0.0.0.0:%s SSL=%s", port, bool(cert and key))
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=port, ssl_certfile=cert, ssl_keyfile=key)