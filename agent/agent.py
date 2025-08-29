import logging
import sys, threading
import asyncio, json, os, socket, platform, getpass, uuid, ctypes, io, time, base64
import hmac, hashlib, secrets
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional
from urllib.parse import urlparse, urlunparse
import ssl
import websockets
from websockets import exceptions as ws_exceptions
from PIL import Image
import mss
import pyautogui
from datetime import datetime
from collections import deque
from dataclasses import dataclass, field
import psutil
try:
    import winreg  # Windows only
except Exception:
    winreg = None  # type: ignore

SERVER_URI = os.environ.get("AGENT_SERVER", "ws://localhost:8765/ws/agent")
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent
CFG = BASE_DIR / "agent_config.json"
DEFAULT_UPLOAD_DIR = os.environ.get("AGENT_UPLOAD_DIR") or str((Path.home() / "Downloads"))
UPLOAD_IDLE_TIMEOUT = 120  # сек без активности -> автоотмена

# === Общий секрет для HMAC (совпадает с сервером) ===
SHARED_SECRET = os.environ.get("SHARED_SECRET", "rpcs_dev_secret_change_me")

# Белый список директорий на агенте (файлы можно трогать только тут)
ALLOWED_ROOTS = [
    Path.home(),
    Path.home() / "Downloads",
    Path("C:/Users/Public")
]

INVALID_NAME_CHARS = set('<>:"/\\|?*')

# глобальные флаги для управления стримом/выходом
STOP_EVENT = threading.Event()
PAUSE_EVENT = threading.Event()

def resolve_server_uri() -> str:
    # 1) CLI: --server=ws://host:8765/ws/agent
    for a in sys.argv[1:]:
        if a.startswith("--server="):
            return _normalize_server_uri(a.split("=", 1)[1])
    # 2) ENV: AGENT_SERVER=ws://host:8765/ws/agent   (или без схемы: host:8765)
    env = os.environ.get("AGENT_SERVER")
    if env:
        return _normalize_server_uri(env)
    # 3) CFG: agent_config.json -> {"server_uri": "..."}
    try:
        if CFG.exists():
            d = json.loads(CFG.read_text(encoding="utf-8"))
            if isinstance(d, dict) and d.get("server_uri"):
                return _normalize_server_uri(str(d["server_uri"]))
    except Exception:
        pass
    # 4) Fallback
    return SERVER_URI

def re_split_servers(raw: str) -> List[str]:
    seps = [",", ";", " "]
    s = raw.strip().strip('"').strip("'")
    for sep in seps:
        s = s.replace(sep, " ")
    return [x for x in s.split() if x]

def _normalize_server_uri(s: str) -> str:
    s = (s or "").strip().strip('"').strip("'").replace("\\", "/")
    if not s:
        return SERVER_URI
    if "://" not in s:
        s = "ws://" + s.lstrip("/")
    p = urlparse(s)
    scheme = "wss" if p.scheme == "wss" else "ws"
    host = (p.hostname or "").strip("[]")
    port = p.port
    path = p.path or ""
    # недопустимые хосты
    if host in ("", "0.0.0.0", "::"):
        host = "127.0.0.1"
    if not path or path == "/":
        path = "/ws/agent"
    netloc = f"{host}:{port}" if port else host
    return urlunparse((scheme, netloc, "/" + path.lstrip("/"), "", "", ""))

def _ssl_context_for(uri: str) -> Optional[ssl.SSLContext]:
    """
    Возвращает SSL-контекст для wss://, иначе None.
    Переменные:
      - AGENT_TLS_INSECURE=1   — не проверять сертификат (dev)
      - AGENT_CA_FILE=path.pem — кастомный CA
      - AGENT_CLIENT_CERT/AGENT_CLIENT_KEY — mTLS (опционально)
    """
    try:
        u = urlparse(uri)
        if u.scheme != "wss":
            return None
        insecure = os.environ.get("AGENT_TLS_INSECURE", "0") == "1"
        ca_file = os.environ.get("AGENT_CA_FILE") or ""
        ctx = ssl.create_default_context()
        if ca_file:
            ctx = ssl.create_default_context(cafile=ca_file)
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        cert = os.environ.get("AGENT_CLIENT_CERT"); key = os.environ.get("AGENT_CLIENT_KEY")
        if cert and key:
            ctx.load_cert_chain(certfile=cert, keyfile=key)
        return ctx
    except Exception:
        return None

def resolve_server_uris() -> Tuple[List[str], str]:
    """
    Возвращает (uris, source), где source ∈ {"cli","env","cfg","default"}.
    Поддержка списка адресов через , ; пробел.
    """
    raw = None
    src = "default"
    for a in sys.argv[1:]:
        if a.startswith("--server="):
            raw = a.split("=", 1)[1]; src = "cli"; break
    if raw is None:
        raw = os.environ.get("AGENT_SERVER"); src = "env" if raw else src
    if raw is None and CFG.exists():
        try:
            d = json.loads(CFG.read_text(encoding="utf-8"))
            if isinstance(d, dict) and d.get("server_uri"):
                raw = str(d["server_uri"]); src = "cfg"
        except Exception:
            pass
    if not raw:
        return [SERVER_URI], src

    seps = [",", ";", " "]
    s = raw.strip().strip('"').strip("'")
    for sep in seps: s = s.replace(sep, " ")
    out: List[str] = []
    for p in [x for x in s.split() if x]:
        n = _normalize_server_uri(p)
        try: h = (urlparse(n).hostname or "")
        except Exception: h = ""
        if h in ("", "0.0.0.0", "::"):  # отбрасываем плохие
            continue
        if n not in out: out.append(n)
    if not out:
        out = ["ws://127.0.0.1:8765/ws/agent"]
    return out, src

def _setup_logging() -> Path:
    try:
        log_dir = Path(os.environ.get("AGENT_LOG_DIR") or Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "RPC-Agent")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "agent.log"
        logging.basicConfig(
            level=logging.INFO,
            filename=str(log_file),
            filemode="a",
            format="%(asctime)s %(levelname)s %(message)s"
        )
        logging.info("Agent starting...")
        return log_file
    except Exception:
        return Path("agent.log")

def set_background_priority():
    try:
        import ctypes
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
        hProc = ctypes.windll.kernel32.GetCurrentProcess()
        ctypes.windll.kernel32.SetPriorityClass(hProc, BELOW_NORMAL_PRIORITY_CLASS)
    except Exception:
        pass

def make_tray_icon():
    # создаём простую иконку 16x16/32x32 в памяти
    try:
        from PIL import Image, ImageDraw, ImageFont
        img = Image.new("RGBA", (32, 32), (10, 18, 35, 255))
        d = ImageDraw.Draw(img)
        d.rounded_rectangle((4, 6, 28, 26), radius=5, outline=(70,120,255,255), width=2)
        d.rectangle((8, 10, 24, 20), fill=(40, 60, 120, 255))
        d.rectangle((14, 22, 18, 24), fill=(70,120,255,255))
        return img
    except Exception:
        return None

def run_tray(aid: str):
    try:
        import pystray
        from pystray import MenuItem as Item, Menu
        icon_img = make_tray_icon()

        def do_connect_now(icon, item):
            # Сбрасываем паузу и просим «подтолкнуть» основной цикл
            PAUSE_EVENT.clear()

        def do_toggle_pause(icon, item):
            if PAUSE_EVENT.is_set():
                PAUSE_EVENT.clear()
            else:
                PAUSE_EVENT.set()

        def do_open_downloads(icon, item):
            try:
                p = os.path.normpath(DEFAULT_UPLOAD_DIR)
                if os.path.isdir(p):
                    os.startfile(p)
            except Exception:
                pass

        def do_exit(icon, item):
            STOP_EVENT.set()
            try:
                icon.stop()
            except Exception:
                pass

        menu = Menu(
            Item(f'Агент: {aid[:8]}…', enabled=False),
            Item('Подключиться сейчас', do_connect_now),
            Item(lambda: 'Пауза стрима: ВЫКЛ' if not PAUSE_EVENT.is_set() else 'Пауза стрима: ВКЛ', do_toggle_pause),
            Item('Открыть папку загрузок', do_open_downloads),
            Item('Выход', do_exit)
        )
        ic = pystray.Icon("RPC Agent", icon=icon_img, title="Remote PC Control Agent", menu=menu)
        ic.run()  # блокирует отдельный поток
    except Exception:
        # если нет pystray — просто тихо не показываем трей
        pass

# === Новое: адаптивный контроллер стрима ===
@dataclass
class AdaptiveConfig:
    screen_w: int
    screen_h: int
    # Текущие параметры
    fps: float = 15.0
    quality: int = 65            # 35..85
    scale: float = 1.0           # 0.5..1.0
    subsampling: int = 2         # 0/1/2 (чем больше, тем меньше)
    # Границы
    min_fps: float = 6.0
    max_fps: float = 30.0
    min_quality: int = 35
    max_quality: int = 85
    min_scale: float = 0.5
    max_scale: float = 1.0
    # Идл‑режим
    idle_seconds: float = 3.0
    last_input_ts: float = 0.0
    # Скользящие метрики
    send_times_ms: deque = field(default_factory=lambda: deque(maxlen=30))
    frame_sizes: deque = field(default_factory=lambda: deque(maxlen=30))
    # Целевой канал вниз (по данным браузера), бит/с
    target_bps: float = 0.0

    def interval(self) -> float:
        return 1.0 / max(self.min_fps, min(self.fps, self.max_fps))

    def effective_fps(self) -> float:
        idle = (time.time() - self.last_input_ts) > self.idle_seconds
        base = max(self.min_fps, min(self.fps, self.max_fps))
        return max(self.min_fps, base * 0.6) if idle else base

    def note_send(self, ms: float, size: int) -> None:
        self.send_times_ms.append(ms)
        self.frame_sizes.append(size)

    def on_input(self) -> None:
        self.last_input_ts = time.time()

    def fit_to_viewport(self, vw: int, vh: int, dpr: float = 1.0) -> None:
        try:
            # Рассчитать масштаб, чтобы поместиться в окно просмотра с учётом DPR
            tw = max(1, int(vw * max(1.0, dpr)))
            th = max(1, int(vh * max(1.0, dpr)))
            sx = tw / self.screen_w
            sy = th / self.screen_h
            new_scale = min(self.max_scale, max(self.min_scale, min(sx, sy, 1.0)))
            # Плавная подстройка
            self.scale = round(0.7 * self.scale + 0.3 * new_scale, 2)
        except Exception:
            pass

    def maybe_adapt(self) -> None:
        # На основе времени отправки и среднего размера кадров
        if not self.send_times_ms:
            return
        avg_ms = sum(self.send_times_ms) / len(self.send_times_ms)
        avg_sz = (sum(self.frame_sizes) / len(self.frame_sizes)) if self.frame_sizes else 0
        # Оценка текущего исходящего битрейта
        est_bps = avg_sz * 8.0 * max(1.0, self.fps)
        congested = avg_ms > 90.0
        over_bps = self.target_bps > 0 and est_bps > self.target_bps * 0.9

        if congested or over_bps:
            # Снижаем по очереди: качество -> масштаб -> FPS
            if self.quality > self.min_quality:
                self.quality = max(self.min_quality, self.quality - 5)
            elif self.scale > self.min_scale:
                self.scale = round(max(self.min_scale, self.scale - 0.1), 2)
            elif self.fps > self.min_fps:
                self.fps = max(self.min_fps, self.fps - 2)
        else:
            # Улучшаем постепенно: масштаб -> качество -> FPS
            if avg_ms < 50 and self.scale < self.max_scale:
                self.scale = round(min(self.max_scale, self.scale + 0.05), 2)
            elif avg_ms < 60 and self.quality < self.max_quality:
                self.quality = min(self.max_quality, self.quality + 3)
            elif avg_ms < 60 and self.fps < self.max_fps:
                self.fps = min(self.max_fps, self.fps + 1)

def is_admin() -> bool:
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception: return False

def load_id() -> str:
    try:
        if CFG.exists() and CFG.stat().st_size>0:
            d=json.loads(CFG.read_text(encoding="utf-8"))
            if isinstance(d,dict) and d.get("agent_id"): return str(d["agent_id"])
    except Exception: pass
    aid=str(uuid.uuid4()); CFG.write_text(json.dumps({"agent_id":aid},ensure_ascii=False,indent=2),encoding="utf-8"); return aid

# --- New: сбор системной информации ---
def get_hostname() -> str:
    return socket.gethostname()

def get_fqdn() -> str:
    try: return socket.getfqdn()
    except Exception: return ""

def get_primary_ip() -> str:
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8",80))
        ip=s.getsockname()[0]; s.close(); return ip
    except Exception:
        try: return socket.gethostbyname(socket.gethostname())
        except Exception: return ""

def get_all_ips() -> List[str]:
    ips: List[str] = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if getattr(a, "family", None) == socket.AF_INET:
                    if a.address and not a.address.startswith("127."):
                        ips.append(a.address)
    except Exception:
        pass
    # уникальные, порядок сохранён
    seen=set(); out=[]
    for x in ips:
        if x not in seen: seen.add(x); out.append(x)
    return out

def norm_mac(m: str) -> str:
    m = m.replace("-", ":").lower()
    if len(m)==12 and ":" not in m:
        m = ":".join(m[i:i+2] for i in range(0,12,2))
    return m

def get_all_macs() -> List[str]:
    macs: List[str] = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                # AF_LINK на разных платформах отличается
                fam = getattr(a, "family", None)
                if str(fam).endswith("AF_LINK") or getattr(a, "family", None) == psutil.AF_LINK if hasattr(psutil, "AF_LINK") else False:
                    mac = getattr(a, "address", "") or ""
                    mac = norm_mac(mac)
                    if mac and mac != "00:00:00:00:00:00":
                        macs.append(mac)
    except Exception:
        pass
    # fallback через uuid
    try:
        hw = uuid.getnode()
        if (hw >> 40) % 2 == 0:  # не локально-администрируемый
            macs.append(norm_mac(f"{hw:012x}"))
    except Exception:
        pass
    # уникальные
    seen=set(); out=[]
    for x in macs:
        if x not in seen: seen.add(x); out.append(x)
    return out

def get_primary_mac(primary_ip: str, macs: List[str]) -> Optional[str]:
    # пытаемся найти MAC интерфейса с primary_ip
    try:
        for name, addrs in psutil.net_if_addrs().items():
            ips = [a.address for a in addrs if getattr(a, "family", None) == socket.AF_INET]
            if primary_ip in ips:
                for a in addrs:
                    fam = getattr(a, "family", None)
                    if str(fam).endswith("AF_LINK") or getattr(a, "family", None) == psutil.AF_LINK if hasattr(psutil, "AF_LINK") else False:
                        m = norm_mac(getattr(a, "address", "") or "")
                        if m and m in macs:
                            return m
    except Exception:
        pass
    return macs[0] if macs else None

def get_cpu_info() -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "model": platform.processor() or "",
        "arch": platform.machine() or "",
        "cores_logical": psutil.cpu_count(logical=True) or 0,
        "cores_physical": psutil.cpu_count(logical=False) or 0,
    }
    try:
        f = psutil.cpu_freq()
        if f: info["freq_mhz"] = int(f.current)
    except Exception:
        pass
    return info

def get_ram_gb() -> float:
    try: return round(psutil.virtual_memory().total / (1024**3), 2)
    except Exception: return 0.0

def get_system_model() -> Dict[str, str]:
    out = {"manufacturer":"", "product_name":""}
    if winreg is None: return out
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as k:
            out["manufacturer"] = winreg.QueryValueEx(k, "SystemManufacturer")[0]
            out["product_name"] = winreg.QueryValueEx(k, "SystemProductName")[0]
    except Exception:
        pass
    return out
# --- /New ---

def screen_size() -> Tuple[int,int]:
    try:
        with mss.mss() as sct:
            m = sct.monitors[1]
            return int(m["width"]), int(m["height"])
    except Exception:
        return pyautogui.size()

def scale_to_screen(x: float, y: float, w: float, h: float, sw: int, sh: int) -> Tuple[int,int]:
    if w<=0 or h<=0: return int(x), int(y)
    return int(x * sw / w), int(y * sh / h)

async def stream_frames(ws, cfg: AdaptiveConfig):
    # Захват полного экрана и кодирование с адаптивными параметрами
    interval_min = 1.0 / cfg.max_fps
    with mss.mss() as sct:
        mon = sct.monitors[1]
        cfg.screen_w, cfg.screen_h = int(mon["width"]), int(mon["height"])
        while True:
            # Пауза стрима по флагу (сильно снижает нагрузку)
            if PAUSE_EVENT.is_set():
                await asyncio.sleep(0.25)
                continue

            loop_start = time.perf_counter()
            # Захват
            img = sct.grab(mon)  # raw BGRA
            pil = Image.frombytes('RGB', img.size, img.rgb)  # RGB
            # Масштабирование
            if cfg.scale < 0.999:
                sw = max(1, int(pil.width * cfg.scale))
                sh = max(1, int(pil.height * cfg.scale))
                pil = pil.resize((sw, sh), Image.BILINEAR)
            # JPEG
            buf = io.BytesIO()
            pil.save(buf, format="JPEG", quality=int(cfg.quality), optimize=True, subsampling=cfg.subsampling)
            payload = buf.getvalue()
            # Отправка
            t0 = time.perf_counter()
            await ws.send(payload)
            send_ms = (time.perf_counter() - t0) * 1000.0
            cfg.note_send(send_ms, len(payload))
            # Адаптация
            cfg.maybe_adapt()
            # Пауза
            target_interval = max(interval_min, 1.0 / max(cfg.min_fps, cfg.effective_fps()))
            elapsed = time.perf_counter() - loop_start
            await asyncio.sleep(max(0.0, target_interval - elapsed))

def key_map(k: str) -> str:
    m = {
        "Escape":"esc","Enter":"enter","Backspace":"backspace","Tab":"tab",
        "Shift":"shift","Control":"ctrl","Alt":"alt","Meta":"win",
        "ArrowLeft":"left","ArrowRight":"right","ArrowUp":"up","ArrowDown":"down",
        "Delete":"delete","Home":"home","End":"end","PageUp":"pageup","PageDown":"pagedown",
        " ":"space"
    }
    if len(k)==1: return k.lower()
    return m.get(k, k.lower())

async def handle_inputs(ws, cfg: AdaptiveConfig):
    sw, sh = screen_size()
    uploads: Dict[str, Any] = {}  # transfer_id -> {"fh","tmp","final","size","written","last_ts"}

    def b64d(s: str) -> bytes:
        return base64.b64decode(s.encode("utf-8"))

    def b64e(b: bytes) -> str:
        return base64.b64encode(b).decode("utf-8")

    async def send_json(obj: Dict[str, Any]):
        try:
            await ws.send(json.dumps(obj, ensure_ascii=False))
        except Exception:
            pass

    def cleanup_upload(tid: str, remove_tmp: bool = True):
        sess = uploads.pop(tid, None)
        if not sess:
            return
        try:
            try:
                sess.get("fh") and sess["fh"].close()
            except Exception:
                pass
            if remove_tmp:
                tmp = sess.get("tmp")
                if tmp and os.path.exists(tmp):
                    try: os.remove(tmp)
                    except Exception: pass
        except Exception:
            pass

    try:
        while True:
            msg = await ws.recv()

            # Периодическая очистка «зависших» аплоадов
            now = time.time()
            for tid, sess in list(uploads.items()):
                if now - sess.get("last_ts", now) > UPLOAD_IDLE_TIMEOUT:
                    cleanup_upload(tid, remove_tmp=True)
                    await send_json({"type":"file_error","transfer_id": tid, "message": "Загрузка отменена по таймауту"})

            if isinstance(msg, str):
                try:
                    data = json.loads(msg)
                except Exception:
                    continue

                t = data.get("type")

                # ---- Сетевые пинги и адаптация ----
                if t == "net_ping":
                    await send_json({"type":"net_pong", "ts": data.get("ts")})
                    continue
                if t == "viewer_info":
                    vp = data.get("viewport") or {}
                    cfg.fit_to_viewport(int(vp.get("w",0)), int(vp.get("h",0)), float(vp.get("dpr",1.0)))
                    continue
                if t == "viewer_stats":
                    rx_bps = float(data.get("rx_bps") or 0.0)
                    if rx_bps > 0:
                        cfg.target_bps = rx_bps * 0.85
                    continue
                if t == "stream_set":
                    if "fps" in data: cfg.fps = float(data["fps"])
                    if "quality" in data: cfg.quality = int(data["quality"])
                    if "scale" in data: cfg.scale = float(data["scale"])
                    continue

                # ---- Управление мышью/клавиатурой ----
                if t == "mouse":
                    cfg.on_input()
                    x = data.get("x",0); y=data.get("y",0); w=data.get("w",1); h=data.get("h",1)
                    sx, sy = scale_to_screen(x, y, w, h, sw, sh)
                    ev = data.get("event")
                    if ev=="move":
                        pyautogui.moveTo(sx, sy, duration=0)
                    elif ev=="down":
                        b = "left" if data.get("button",0)==0 else ("middle" if data.get("button")==1 else "right")
                        pyautogui.mouseDown(x=sx, y=sy, button=b)
                    elif ev=="up":
                        b = "left" if data.get("button",0)==0 else ("middle" if data.get("button")==1 else "right")
                        pyautogui.mouseUp(x=sx, y=sy, button=b)
                    elif ev=="wheel":
                        delta = int(data.get("delta",0))
                        pyautogui.scroll(-int(delta/10), x=sx, y=sy)
                    continue
                if t == "key":
                    cfg.on_input()
                    k = key_map(str(data.get("key",""))); ev = data.get("event")
                    if k:
                        try:
                            if ev=="down": pyautogui.keyDown(k)
                            elif ev=="up": pyautogui.keyUp(k)
                        except Exception:
                            pass
                    continue

                # ---- Файлы: листинг ----
                if t == "file_list":
                    path = str(data.get("path") or "") or "C:\\"
                    safe = _is_allowed_path(path)
                    if not safe:
                        await send_json({"type":"file_error","message":"Путь вне разрешённых директорий"})
                        continue
                    try:
                        items = []
                        with os.scandir(safe) as it:
                            for entry in it:
                                try:
                                    info = entry.stat()
                                    items.append({
                                        "name": entry.name,
                                        "is_dir": entry.is_dir(),
                                        "size": int(info.st_size),
                                        "mtime": int(info.st_mtime)
                                    })
                                except Exception:
                                    pass
                        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
                        await send_json({"type":"file_list_result","path": safe, "items": items})
                    except Exception as e:
                        await send_json({"type":"file_error","message": f"Листинг не удался: {e}"})
                    continue

                # ---- Файлы: upload (viewer -> агент) ----
                if t == "file_upload_begin":
                    tid = str(data.get("transfer_id") or "")
                    name = os.path.basename(str(data.get("name") or "upload.bin"))
                    size = int(data.get("size") or 0)
                    dest_dir = str(data.get("dest_dir") or DEFAULT_UPLOAD_DIR)
                    final_path = _safe_join(dest_dir, name)
                    if not final_path:
                        await send_json({"type":"file_error","message":"Недопустимое имя или директория вне белого списка","transfer_id":tid})
                        continue
                    try:
                        os.makedirs(os.path.dirname(final_path), exist_ok=True)
                        tmp_path = final_path + ".part"
                        fh = open(tmp_path, "wb")
                        uploads[tid] = {
                            "fh": fh, "tmp": tmp_path, "final": final_path,
                            "size": size, "written": 0, "last_ts": time.time()
                        }
                        await send_json({"type":"file_upload_ack","transfer_id": tid, "path": final_path})
                    except Exception as e:
                        await send_json({"type":"file_error","message": f"Не удалось открыть файл для записи: {e}", "transfer_id": tid})
                    continue

                if t == "file_upload_chunk":
                    tid = str(data.get("transfer_id") or "")
                    sess = uploads.get(tid)
                    if not sess:
                        await send_json({"type":"file_error","message":"Неизвестная сессия загрузки","transfer_id":tid})
                        continue
                    try:
                        buf = b64d(str(data.get("data_b64") or ""))
                        sess["fh"].write(buf)
                        sess["written"] += len(buf)
                        sess["last_ts"] = time.time()
                    except Exception as e:
                        await send_json({"type":"file_error","message": f"Ошибка записи: {e}", "transfer_id": tid})
                    continue

                if t == "file_upload_end":
                    tid = str(data.get("transfer_id") or "")
                    sess = uploads.pop(tid, None)
                    if sess:
                        try:
                            try: sess["fh"].close()
                            except Exception: pass
                            # атомарно переименуем .part -> финальный (без «видимого» открытого файла в системе)
                            os.replace(sess["tmp"], sess["final"])
                            await send_json({"type":"file_upload_done","transfer_id": tid, "path": sess.get("final")})
                        except Exception as e:
                            # при ошибке — попытаться убрать временный файл
                            try:
                                if os.path.exists(sess["tmp"]):
                                    os.remove(sess["tmp"])
                            except Exception:
                                pass
                            await send_json({"type":"file_error","message": f"Завершение загрузки не удалось: {e}", "transfer_id": tid})
                    continue

                if t == "file_upload_cancel":
                    tid = str(data.get("transfer_id") or "")
                    cleanup_upload(tid, remove_tmp=True)
                    await send_json({"type":"file_error","transfer_id": tid, "message": "Загрузка отменена пользователем"})
                    continue

                # ---- Файлы: download (агент -> viewer) ----
                if t == "file_download_begin":
                    tid = str(data.get("transfer_id") or "")
                    path = str(data.get("path") or "")
                    safe = _is_allowed_path(path)
                    if not safe:
                        await send_json({"type":"file_error","message":"Путь вне разрешённых директорий","transfer_id":tid})
                        continue
                    name = os.path.basename(safe) or "download.bin"
                    try:
                        size = os.path.getsize(safe)
                        await send_json({"type":"file_download_meta","transfer_id": tid, "name": name, "size": int(size)})
                        with open(safe, "rb") as fh:
                            chunk = fh.read(64*1024)
                            while chunk:
                                await send_json({"type":"file_download_chunk","transfer_id": tid, "data_b64": b64e(chunk)})
                                chunk = fh.read(64*1024)
                        await send_json({"type":"file_download_end","transfer_id": tid})
                    except Exception as e:
                        await send_json({"type":"file_error","message": f"Скачивание не удалось: {e}", "transfer_id": tid})
                    continue

                # прочее игнорируем
            else:
                # бинарных команд тут нет
                continue
    finally:
        # Гарантированное закрытие всех незавершённых загрузок при выходе (разрыв/ws.close)
        for tid in list(uploads.keys()):
            cleanup_upload(tid, remove_tmp=True)

def build_hello_payload(agent_id: str) -> Dict[str, Any]:
    host = get_hostname()
    ip = get_primary_ip()
    ips = get_all_ips()
    macs = get_all_macs()
    payload: Dict[str, Any] = {
        "agent_id": agent_id,
        "host": host,
        "fqdn": get_fqdn(),
        "user": getpass.getuser(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "ip": ip,
        "ips": ips,
        "mac": get_primary_mac(ip, macs) or "",
        "macs": macs,
        "admin": is_admin(),
        "hardware": {
            "cpu": get_cpu_info(),
            "ram_gb": get_ram_gb(),
            "machine": platform.machine() or "",
            "system_model": get_system_model(),
        },
        "screen": {}
    }
    w,h = screen_size()
    payload["screen"] = {"width": w, "height": h}

    # Добавляем HMAC‑аутентификацию
    ts = int(time.time())
    nonce = secrets.token_hex(16)
    payload["auth"] = {"ts": ts, "nonce": nonce, "sig": _sign_hello(agent_id, ts, nonce)}
    return payload

async def connect_once(aid: str, uri: str) -> bool:
    try:
        u = urlparse(uri)
        if (u.hostname in ("127.0.0.1", "localhost", "::1")):
            logging.warning("AGENT_SERVER указывает на loopback (%s). Для удалённого ПК задайте IP сервера в сети.", u.hostname)

        ssl_ctx = _ssl_context_for(uri)
        async with websockets.connect(
            uri,
            ping_interval=20,
            ping_timeout=20,
            max_size=10 * 1024 * 1024,
            ssl=ssl_ctx
        ) as ws:
            hello = build_hello_payload(aid)
            await ws.send(json.dumps(hello, ensure_ascii=False))
            resp = await asyncio.wait_for(ws.recv(), timeout=10)
            if isinstance(resp, (bytes, bytearray)):
                try: resp = resp.decode("utf-8", "ignore")
                except Exception: pass
            if resp != "OK":
                logging.warning("handshake resp: %s", resp)
                return False
            logging.info("handshake OK")

            await ws.wait_closed()
            logging.info("ws closed: code=%s reason=%s", getattr(ws,"close_code",None), getattr(ws,"close_reason",""))
            return False

    except ws_exceptions.InvalidMessage:
        # Сервер, вероятно, слушает wss, а мы пришли по ws — переключаемся
        if uri.startswith("ws://"):
            alt = "wss://" + uri[len("ws://"):]
            logging.warning("InvalidMessage на %s; пробуем %s", uri, alt)
            return await connect_once(aid, alt)
        logging.exception("connect_once error")
        return False
    except ssl.SSLCertVerificationError:
        logging.error("TLS verify failed. Установите AGENT_TLS_INSECURE=1 или укажите AGENT_CA_FILE")
        return False
    except Exception:
        logging.exception("connect_once error")
        return False

def _is_allowed_path(p: str) -> Optional[str]:
    try:
        rp = Path(p).resolve(strict=False)
        for root in ALLOWED_ROOTS:
            try:
                if rp.is_relative_to(root.resolve(strict=True) if root.exists() else root):
                    return str(rp)
            except Exception:
                # is_relative_to есть в Py3.9+, делаем запасной вариант
                try:
                    r = root.resolve(strict=False)
                    if str(rp).lower().startswith((str(r) + os.sep).lower()):
                        return str(rp)
                except Exception:
                    pass
        return None
    except Exception:
        return None

def _valid_filename(name: str) -> bool:
    return bool(name) and not any(c in INVALID_NAME_CHARS for c in name)

def _safe_join(dest_dir: str, name: str) -> Optional[str]:
    if not _valid_filename(name):
        return None
    base = _is_allowed_path(dest_dir)
    if not base:
        return None
    full = Path(base) / name
    return _is_allowed_path(str(full))

def _sign_hello(agent_id: str, ts: int, nonce: str) -> str:
    msg = f"{agent_id}|{ts}|{nonce}".encode("utf-8")
    return hmac.new(SHARED_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()

async def main():
    set_background_priority()
    log_file = _setup_logging()
    uris, src = resolve_server_uris()
    logging.info(f"SERVER_URIS[{src}]={uris}")
    if SHARED_SECRET == "rpcs_dev_secret_change_me":
        logging.warning("SHARED_SECRET has default value. Change for production.")
    if not is_admin():
        logging.info("Not admin. Keyboard/mouse may be limited.")

    aid = load_id()
    logging.info(f"agent_id={aid}")

    tray_thread = threading.Thread(target=run_tray, args=(aid,), daemon=True)
    tray_thread.start()

    delay = 2.0
    while not STOP_EVENT.is_set():
        ok = False
        for uri in uris:
            try:
                logging.info(f"try connect: {uri}")
                ok = await connect_once(aid, uri)
                logging.info(f"connect_once result: {ok} ({uri})")
                if ok: break
            except Exception:
                logging.exception("connect_once failed")
                ok = False

        if STOP_EVENT.is_set():
            break
        await asyncio.sleep(delay if not ok else 2.0)
        delay = min(30.0, delay*1.5 if not ok else 2.0)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass