import sqlite3, json
import os, socket
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Set, Tuple
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import hmac, hashlib, time, secrets, ipaddress
from urllib.parse import parse_qs

APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web"
DB_PATH = APP_DIR / "server.sqlite3"

# Гарантируем наличие health для проверки
try:
    from fastapi import FastAPI
except NameError:
    app = FastAPI()

# === Вшитая защита (можно сменить значения) ===
SHARED_SECRET = os.environ.get("SHARED_SECRET", "rpcs_dev_secret_change_me")

# Инициализируем FastAPI один раз
app = FastAPI(title="Remote PC Control (Stream)")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

# общий секрет для HMAC (агент <-> сервер)
VIEWER_TOKEN  = "view_dev_token"                  # токен для WebSocket зрителя (браузер)
AUTH_TS_SKEW  = int(os.environ.get("AUTH_TS_SKEW", "-1")) # допуск по времени (сек)
NONCE_TTL     = int(os.environ.get("NONCE_TTL", "180")) # время жизни nonce (сек)
_auth_nonces: Dict[str, float] = {}               # nonce -> ts

# Онлайн-реестр: агенты и их зрители
active_agents: Dict[str, Dict[str, Any]] = {}   # agent_id -> {"ws": WebSocket, "info": dict}
viewers: Dict[str, Set[WebSocket]] = {}         # agent_id -> set(viewer WebSocket)

def _check_sig(hello: Dict[str, Any]) -> bool:
    try:
        aid = str(hello["agent_id"])
        auth = hello.get("auth") or {}
        ts = int(auth["ts"])
        nonce = str(auth["nonce"])
        sig = str(auth["sig"])
        msg = f"{aid}|{ts}|{nonce}".encode("utf-8")
        expect = hmac.new(SHARED_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expect, sig)
    except Exception:
        return False

def _auth_verify_hello_ex(hello: Dict[str, Any]) -> Tuple[bool, str]:
    try:
        a = hello.get("auth") or {}
        agent_id = str(hello.get("agent_id") or "")
        try:
            ts = int(a.get("ts") or 0)
        except Exception:
            ts = 0
        nonce = str(a.get("nonce") or "")
        sig = str(a.get("sig") or "")
        if not agent_id:
            return False, "no_agent_id"
        if not (nonce and sig):
            return False, "no_nonce_or_sig"
        if AUTH_TS_SKEW >= 0 and abs(int(time.time()) - ts) > AUTH_TS_SKEW:
            return False, "ts_skew"
        _auth_cleanup()
        if nonce in _auth_nonces:
            return False, "replay_nonce"
        msg = f"{agent_id}|{ts}|{nonce}".encode("utf-8")
        expect = hmac.new(SHARED_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            return False, "bad_sig"
        _auth_nonces[nonce] = time.time()
        return True, "ok"
    except Exception as e:
        return False, f"error:{e}"

def _auth_cleanup():
    now = time.time()
    for n, ts in list(_auth_nonces.items()):
        if now - ts > NONCE_TTL:
            _auth_nonces.pop(n, None)

def _auth_verify_hello(hello: Dict[str, Any]) -> bool:
    try:
        a = hello.get("auth") or {}
        agent_id = str(hello.get("agent_id") or "")
        # ts может быть любым; если AUTH_TS_SKEW<0 — не проверяем время
        try:
            ts = int(a.get("ts") or 0)
        except Exception:
            ts = 0
        nonce = str(a.get("nonce") or "")
        sig = str(a.get("sig") or "")
        if not (agent_id and nonce and sig):
            return False
        # проверка времени
        if AUTH_TS_SKEW >= 0 and abs(int(time.time()) - ts) > AUTH_TS_SKEW:
            return False
        # анти‑replay по nonce
        _auth_cleanup()
        if nonce in _auth_nonces:
            return False
        msg = f"{agent_id}|{ts}|{nonce}".encode("utf-8")
        expect = hmac.new(SHARED_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            return False
        _auth_nonces[nonce] = time.time()
        return True
    except Exception:
        return False

# (опционально) ограничение по IP для агентов (частные сети)
PRIVATE_NETS = [ipaddress.ip_network(x) for x in ("127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")]

# Разрешить подключения с публичных IP (по умолчанию включено)
ALLOW_PUBLIC_AGENTS = os.environ.get("ALLOW_PUBLIC_AGENTS", "1") == "1"

def _ip_in_private(peer: str) -> bool:
    try:
        ip = ipaddress.ip_address(peer)
        return any(ip in net for net in PRIVATE_NETS)
    except Exception:
        return False

def db_init():
    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL)")
        cur.execute("""CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY, hostname TEXT, group_id INTEGER, last_seen TEXT, info_json TEXT,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        )""")
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
                hostname=excluded.hostname, last_seen=excluded.last_seen, info_json=excluded.info_json
        """, (agent_id, hostname, now, json.dumps(info, ensure_ascii=False)))
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
        out = []
        for r in rows:
            aid, host, gid, last_seen, info_json, gname = r
            try:
                info = json.loads(info_json) if info_json else {}
            except Exception:
                info = {}
            out.append({"agent_id": aid, "hostname": host, "group_id": gid, "group_name": gname, "last_seen": last_seen, "info": info})
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
    if not name.strip(): raise HTTPException(400, "empty name")
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

@app.on_event("startup")
def _startup():
    WEB_DIR.mkdir(parents=True, exist_ok=True)
    db_init()

@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse((WEB_DIR / "index.html").read_text(encoding="utf-8"))

@app.get("/view/{agent_id}", response_class=HTMLResponse)
def view_agent(agent_id: str):
    html = (WEB_DIR / "view.html").read_text(encoding="utf-8")
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

@app.websocket("/ws/agent")
async def ws_agent(ws: WebSocket):
    # Можно отсеивать по IP (вкл./выкл. через ALLOW_PUBLIC_AGENTS)
    try:
        peer = ws.client.host if ws.client else ""
        if (not ALLOW_PUBLIC_AGENTS) and peer and not _ip_in_private(peer):
            await ws.close(code=1008); return
    except Exception:
        peer = "?"
    await ws.accept()
    agent_id = None
    try:
        hello = await ws.receive_json()
        ok, reason = _auth_verify_hello_ex(hello)
        if not ok:
            logging.warning("AUTH FAIL peer=%s aid=%s reason=%s", peer, str(hello.get("agent_id") or ""), reason)
            try: await ws.send_text(f"ERR_AUTH:{reason}")
            except Exception: pass
            await ws.close(code=1008); return

        agent_id = str(hello.get("agent_id") or "").strip()
        hostname = str(hello.get("host") or "").strip()
        if not agent_id:
            logging.warning("HELLO ERR empty agent_id, peer=%s", peer)
            await ws.send_text("ERR"); await ws.close(code=1008); return

        # Не роняем рукопожатие, если БД упала — логируем и продолжаем
        try:
            db_upsert_agent(agent_id, hostname, hello)
        except Exception as e:
            logging.exception("db_upsert_agent failed: %s", e)

        active_agents[agent_id] = {"ws": ws, "info": hello, "since": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        viewers.setdefault(agent_id, set())
        await ws.send_text("OK")
        logging.info("AGENT ONLINE: %s (%s) from %s", agent_id, hostname, peer)

        while True:
            message = await ws.receive()
            mtype = message.get("type")
            if mtype == "websocket.disconnect":
                break
            if "bytes" in message and message["bytes"] is not None:
                frame = message["bytes"]
                dead: List[WebSocket] = []
                for vw in list(viewers.get(agent_id, set())):
                    try:
                        await vw.send_bytes(frame)
                    except Exception:
                        dead.append(vw)
                for d in dead:
                    viewers.get(agent_id, set()).discard(d)
            elif "text" in message and message["text"] is not None:
                txt = message["text"]
                if len(txt) > 512_000:
                    continue
                dead: List[WebSocket] = []
                for vw in list(viewers.get(agent_id, set())):
                    try:
                        await vw.send_text(txt)
                    except Exception:
                        dead.append(vw)
                for d in dead:
                    viewers.get(agent_id, set()).discard(d)
                try:
                    db_upsert_agent(agent_id, hostname, hello)
                except Exception as e:
                    logging.exception("db_upsert_agent failed (loop): %s", e)
    except WebSocketDisconnect:
        logging.info("WS disconnect from %s (aid=%s)", peer, agent_id or "?")
    except Exception as e:
        logging.exception("WS agent error: %s", e)
        try: await ws.close()
        except Exception: pass
    finally:
        if agent_id:
            active_agents.pop(agent_id, None)
            logging.info("AGENT OFFLINE: %s", agent_id)

# Простой healthcheck
@app.get("/health")
async def health():
    return {"status": "ok"}

# === WebSocket зрителя с проверкой токена ===
@app.websocket("/ws/view/{agent_id}")
async def ws_view(ws: WebSocket, agent_id: str):
    # Проверяем токен из query (?token=...)
    qp = parse_qs(ws.url.query or "")
    token = (qp.get("token") or [""])[0]
    if token != VIEWER_TOKEN:
        await ws.close(code=1008); return

    await ws.accept()
    # Регистрируем зрителя
    viewers.setdefault(agent_id, set()).add(ws)
    try:
        # Проксирование команд от зрителя к агенту
        while True:
            msg = await ws.receive_text()
            if len(msg) > 128_000:  # базовый лимит
                continue
            ag = active_agents.get(agent_id, {})
            aws: WebSocket = ag.get("ws")
            if aws:
                await aws.send_text(msg)
    except WebSocketDisconnect:
        pass
    finally:
        try: viewers.get(agent_id, set()).discard(ws)
        except Exception: pass

@app.get("/bootstrap.ps1")
def bootstrap_ps1(
    request: Request,
    host: str | None = Query(default=None, description="IP или хост сервера, например 192.168.1.50"),
    port: int | None = Query(default=None, description="Порт сервера, по умолчанию 8765"),
    insecure: int | None = Query(default=None, description="1 — не проверять TLS (dev)")
):
    # определяем host: сначала из параметра ?host=, затем из заголовка Host, иначе берём локальный IP
    req_host = host or (request.headers.get("host") or "")
    # вытащим только хост без порта, если пришёл host:port
    if ":" in req_host:
        h, _, p = req_host.rpartition(":")
        try:
            # если host был вида [::1]:8765
            if h.startswith("[") and h.endswith("]"):
                h = h[1:-1]
        except Exception:
            pass
        req_host = h
        if not port:
            try: port = int(p)
            except Exception: pass
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
    secret = os.environ.get("SHARED_SECRET", "rpcs_dev_secret_change_me")
    tls_insecure = insecure if insecure is not None else (1 if ssl_on else 0)

    ps = f"""$ErrorActionPreference = "Stop"
$dir = Join-Path $env:LOCALAPPDATA "RPC-Agent"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir "rpc-agent.exe"

Write-Host "Скачиваю агента..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "{download_url}" -OutFile $exe

Write-Host "Настраиваю переменные окружения..." -ForegroundColor Cyan
setx SHARED_SECRET "{secret}" | Out-Null
setx AGENT_SERVER "{ws_uri}" | Out-Null
{"setx AGENT_TLS_INSECURE \"1\" | Out-Null" if tls_insecure else ""}

Write-Host "Запускаю агента..." -ForegroundColor Cyan
Start-Process -FilePath $exe
Write-Host "Готово. Агент запущен и подключится к {ws_uri}." -ForegroundColor Green
"""
    return PlainTextResponse(ps, media_type="text/plain; charset=utf-8")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8765"))
    cert = os.environ.get("SSL_CERTFILE") or None
    key  = os.environ.get("SSL_KEYFILE") or None
    uvicorn.run("app:app", host="0.0.0.0", port=port, ssl_certfile=cert, ssl_keyfile=key)
                