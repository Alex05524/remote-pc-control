from __future__ import annotations

import asyncio
import base64
import ctypes
import getpass
import hashlib
import hmac
import io
import json
import logging
import os
import platform
import secrets
import socket
import sys
import threading
import time
import uuid
import string
import shutil
import zipfile
import mimetypes
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import mss
import psutil
import pyautogui
import ssl
import websockets
from PIL import Image
from websockets.legacy.client import WebSocketClientProtocol
from websockets import exceptions as ws_exceptions

try:
    import winreg  # Windows only
except Exception:  # pragma: no cover
    winreg = None  # type: ignore

pyautogui.FAILSAFE = False

SERVER_URI = os.environ.get("AGENT_SERVER", "ws://localhost:8765/ws/agent")
BASE_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
CFG = BASE_DIR / "agent_config.json"
DEFAULT_UPLOAD_DIR = os.environ.get("AGENT_UPLOAD_DIR") or str(Path.home() / "Downloads")
UPLOAD_IDLE_TIMEOUT = 120  # секунд
SHARED_SECRET = os.environ.get("SHARED_SECRET", "rpcs_dev_secret_change_me")
DEFAULT_SERVER_URIS: List[str] = [
    os.environ.get("AGENT_SERVER_DEFAULT", "ws://127.0.0.1:8765/ws/agent")  # замените на свой публичный URI
]
SERVER_URI = os.environ.get("AGENT_SERVER", DEFAULT_SERVER_URIS[0])

ALLOWED_ROOTS: List[Path] = [
    Path.home(),
    Path.home() / "Downloads",
    Path("C:/Users/Public") if platform.system().lower() == "windows" else Path("/tmp"),
]

INVALID_NAME_CHARS = set('<>:"/\\|?*')

STOP_EVENT = threading.Event()
PAUSE_EVENT = threading.Event()
FULL_FS_MODE = os.environ.get("AGENT_FULL_FS", "1") == "1"  # 1 = видеть все диски (Windows)
PREVIEW_MAX_SIZE = 1_000_000   # 1MB
SEARCH_MAX_RESULTS = 800
SEARCH_DEFAULT_DEPTH = 4

class ImmediateRetry(Exception):
    """Запросить немедленное переключение на следующий URI без роста задержки."""
    pass

def list_drives():
    drives=[]
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i,l in enumerate(string.ascii_uppercase):
        if bitmask & (1<<i):
            path = f"{l}:\\"
            drives.append({"path":path,"label":path})
    return drives

def _list_directory(target: str | None) -> Tuple[str, List[Dict[str, Any]]]:
    if not target:
        drives = []
        for letter in string.ascii_uppercase:
            root = Path(f"{letter}:\\")
            if root.exists():
                drives.append({"name": f"{letter}:\\", "is_dir": True, "size": None})
        return "", drives

    p = Path(target).expanduser()

    if not p.exists():
        raise FileNotFoundError(f"Путь не найден: {target}")
    if p.is_file():
        parent = str(p.parent)
        return parent if parent != "." else "", [{
            "name": p.name,
            "is_dir": False,
            "size": p.stat().st_size,
        }]

    items: List[Dict[str, Any]] = []
    for entry in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
        try:
            size = entry.stat().st_size if entry.is_file() else None
        except OSError:
            size = None
        items.append({
            "name": entry.name,
            "is_dir": entry.is_dir(),
            "size": size,
        })
    return str(p), items


async def handle_message(self, msg: Dict[str, Any]):
    msg_type = msg.get("type")
    if msg_type == "file_list":
        requested = msg.get("path")
        try:
            current_path, items = _list_directory(requested)
            await self.send_json({
                "type": "file_list_result",
                "path": current_path,
                "items": items,
            })
        except Exception as exc:
            await self.send_json({
                "type": "file_error",
                "message": str(exc),
            })
        return

def _ws_is_closed(ws: WebSocketClientProtocol) -> bool:
    try:
        closed = getattr(ws, "closed")
        if isinstance(closed, bool):
            return closed
    except Exception:
        pass
    close_code = getattr(ws, "close_code", None)
    if close_code is not None:
        return True
    state = getattr(ws, "state", None)
    if state is not None and "CLOSED" in str(state).upper():
        return True
    return False

def _safe_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _capture_with_fallback(sct: mss.mss, monitor: Dict[str, Any]) -> Optional[Image.Image]:
    try:
        frame = sct.grab(monitor)
        return Image.frombytes("RGB", frame.size, frame.rgb)
    except Exception as exc:
        logging.warning("MSS grab failed (%s); fallback to pyautogui", exc)
        try:
            screenshot = pyautogui.screenshot()
            return screenshot.convert("RGB")
        except Exception:
            logging.exception("pyautogui fallback failed")
            return None

def resolve_server_uri() -> str:
    uris, _ = resolve_server_uris()
    return uris[0]


def resolve_server_uris() -> Tuple[List[str], str]:
    sources: List[str] = []
    unique: List[str] = []

    def append(raw: Any, label: str) -> None:
        added = False
        for candidate in _collect_uri_candidates(raw):
            normalized = _normalize_server_uri(candidate)
            if normalized not in unique:
                unique.append(normalized)
                added = True
        if added:
            sources.append(label)

    cli_raw: Optional[str] = None
    for arg in sys.argv[1:]:
        if arg.startswith("--server="):
            cli_raw = arg.split("=", 1)[1]
            break
    if cli_raw is not None:
        append(cli_raw, "cli")

    env_raw = os.environ.get("AGENT_SERVER")
    if env_raw:
        append(env_raw, "env")

    env_list_raw = os.environ.get("AGENT_SERVER_URIS")
    if env_list_raw:
        append(env_list_raw, "env_list")

    if CFG.exists():
        try:
            cfg_data = json.loads(CFG.read_text(encoding="utf-8"))
            if isinstance(cfg_data, dict):
                append(cfg_data.get("server_uri"), "cfg")
                append(cfg_data.get("server_uris"), "cfg_list")
        except Exception:
            pass

    if not unique:
        for default_uri in DEFAULT_SERVER_URIS:
            if default_uri not in unique:
                unique.append(default_uri)
        sources.append("default")

    source_label = "+".join(sources) if sources else "default"
    logging.debug("resolve_server_uris -> %s (sources=%s)", unique, source_label)
    return unique, source_label


def _normalize_server_uri(value: str) -> str:
    value = (value or "").strip().strip('"').strip("'").replace("\\", "/")
    if not value:
        return DEFAULT_SERVER_URIS[0]
    if "://" not in value:
        value = "ws://" + value.lstrip("/")
    parsed = urlparse(value)
    scheme = "wss" if parsed.scheme == "wss" else "ws"
    host = (parsed.hostname or "").strip("[]")
    port = parsed.port
    if port is None:
        port = 443 if scheme == "wss" else 80
    path = parsed.path or ""
    if host in ("", "0.0.0.0", "::"):
        host = "127.0.0.1"
    if not path or path == "/":
        path = "/ws/agent"
    host_fmt = f"[{host}]" if ":" in host and not host.startswith("[") else host
    netloc = f"{host_fmt}:{port}" if port else host_fmt
    return urlunparse((scheme, netloc, "/" + path.lstrip("/"), "", "", ""))

def _collect_uri_candidates(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return []
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, (list, tuple)):
                return [str(x).strip() for x in parsed if str(x).strip()]
        except json.JSONDecodeError:
            pass
        tmp = stripped.strip('"').strip("'")
        for sep in (",", ";"):
            tmp = tmp.replace(sep, " ")
        return [segment for segment in tmp.split() if segment]
    if isinstance(raw, (list, tuple, set)):
        return [str(item).strip() for item in raw if str(item).strip()]
    return []

def _ssl_context_for(uri: str) -> Optional[ssl.SSLContext]:
    try:
        parsed = urlparse(uri)
        if parsed.scheme != "wss":
            return None
        insecure = os.environ.get("AGENT_TLS_INSECURE") == "1"
        ca_file = os.environ.get("AGENT_CA_FILE") or None
        ctx = ssl.create_default_context(cafile=ca_file)
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        cert = os.environ.get("AGENT_CLIENT_CERT")
        key = os.environ.get("AGENT_CLIENT_KEY")
        if cert and key:
            ctx.load_cert_chain(certfile=cert, keyfile=key)
        return ctx
    except Exception:
        return None


def _setup_logging() -> Path:
    try:
        log_dir = Path(os.environ.get("AGENT_LOG_DIR") or Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "RPC-Agent")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "agent.log"
        logging.basicConfig(
            level=logging.INFO,
            filename=str(log_file),
            filemode="a",
            format="%(asctime)s %(levelname)s %(message)s",
        )
        logging.info("Agent starting...")
        return log_file
    except Exception:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
        return Path("agent.log")


def set_background_priority() -> None:
    if platform.system().lower() != "windows":
        return
    try:
        below_normal = 0x00004000
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        ctypes.windll.kernel32.SetPriorityClass(handle, below_normal)
    except Exception:
        pass


def make_tray_icon():
    try:
        from PIL import ImageDraw

        img = Image.new("RGBA", (32, 32), (10, 18, 35, 255))
        draw = ImageDraw.Draw(img)
        draw.rounded_rectangle((4, 6, 28, 26), radius=5, outline=(70, 120, 255, 255), width=2)
        draw.rectangle((8, 10, 24, 20), fill=(40, 60, 120, 255))
        draw.rectangle((14, 22, 18, 24), fill=(70, 120, 255, 255))
        return img
    except Exception:  # pragma: no cover
        return None


def run_tray(agent_id: str) -> None:
    try:
        import pystray
        from pystray import Menu, MenuItem as Item

        icon_img = make_tray_icon()

        def do_connect_now(_icon, _item):
            PAUSE_EVENT.clear()

        def do_toggle_pause(_icon, _item):
            if PAUSE_EVENT.is_set():
                PAUSE_EVENT.clear()
            else:
                PAUSE_EVENT.set()

        def do_open_downloads(_icon, _item):
            try:
                path = os.path.normpath(DEFAULT_UPLOAD_DIR)
                if os.path.isdir(path):
                    os.startfile(path)
            except Exception:
                pass

        def do_exit(icon, _item):
            STOP_EVENT.set()
            try:
                icon.stop()
            except Exception:
                pass

        menu = Menu(
            Item(f"Агент: {agent_id[:8]}…", enabled=False),
            Item("Подключиться сейчас", do_connect_now),
            Item(lambda: "Пауза стрима: ВКЛ" if PAUSE_EVENT.is_set() else "Пауза стрима: ВЫКЛ", do_toggle_pause),
            Item("Открыть папку загрузок", do_open_downloads),
            Item("Выход", do_exit),
        )
        icon = pystray.Icon("RPC Agent", icon=icon_img, title="Remote PC Control Agent", menu=menu)
        icon.run()
    except Exception:  # pragma: no cover
        pass


@dataclass
class AdaptiveConfig:
    screen_w: int
    screen_h: int
    fps: float = 15.0
    quality: int = 65
    scale: float = 1.0
    subsampling: int = 2
    min_fps: float = 6.0
    max_fps: float = 30.0
    min_quality: int = 35
    max_quality: int = 85
    min_scale: float = 0.5
    max_scale: float = 1.0
    idle_seconds: float = 3.0
    last_input_ts: float = field(default_factory=time.time)
    send_times_ms: deque = field(default_factory=lambda: deque(maxlen=30))
    frame_sizes: deque = field(default_factory=lambda: deque(maxlen=30))
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
            tw = max(1, int(vw * max(1.0, dpr)))
            th = max(1, int(vh * max(1.0, dpr)))
            sx = tw / self.screen_w
            sy = th / self.screen_h
            new_scale = min(self.max_scale, max(self.min_scale, min(sx, sy, 1.0)))
            self.scale = round(0.7 * self.scale + 0.3 * new_scale, 2)
        except Exception:
            pass

    def maybe_adapt(self) -> None:
        if not self.send_times_ms:
            return
        avg_ms = sum(self.send_times_ms) / len(self.send_times_ms)
        avg_size = (sum(self.frame_sizes) / len(self.frame_sizes)) if self.frame_sizes else 0
        estimate_bps = avg_size * 8.0 * max(1.0, self.fps)
        congested = avg_ms > 90.0
        over_target = self.target_bps > 0 and estimate_bps > self.target_bps * 0.9

        if congested or over_target:
            if self.quality > self.min_quality:
                self.quality = max(self.min_quality, self.quality - 5)
            elif self.scale > self.min_scale:
                self.scale = round(max(self.min_scale, self.scale - 0.1), 2)
            elif self.fps > self.min_fps:
                self.fps = max(self.min_fps, self.fps - 2)
        else:
            if avg_ms < 50 and self.scale < self.max_scale:
                self.scale = round(min(self.max_scale, self.scale + 0.05), 2)
            elif avg_ms < 60 and self.quality < self.max_quality:
                self.quality = min(self.max_quality, self.quality + 3)
            elif avg_ms < 60 and self.fps < self.max_fps:
                self.fps = min(self.max_fps, self.fps + 1)


def is_admin() -> bool:
    if platform.system().lower() == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    return False


def load_id() -> str:
    try:
        if CFG.exists() and CFG.stat().st_size > 0:
            data = json.loads(CFG.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("agent_id"):
                return str(data["agent_id"])
    except Exception:
        pass
    agent_id = str(uuid.uuid4())
    try:
        CFG.write_text(json.dumps({"agent_id": agent_id}, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass
    return agent_id


def get_hostname() -> str:
    return socket.gethostname()


def get_fqdn() -> str:
    try:
        return socket.getfqdn()
    except Exception:
        return ""


def get_primary_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.4)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return ""


def get_all_ips() -> List[str]:
    result: List[str] = []
    try:
        for addresses in psutil.net_if_addrs().values():
            for addr in addresses:
                if getattr(addr, "family", None) == socket.AF_INET:
                    ip = getattr(addr, "address", "")
                    if ip and not ip.startswith("127."):
                        result.append(ip)
    except Exception:
        pass
    seen: set[str] = set()
    ordered: List[str] = []
    for ip in result:
        if ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def norm_mac(value: str) -> str:
    value = value.replace("-", ":").lower()
    if len(value) == 12 and ":" not in value:
        value = ":".join(value[i : i + 2] for i in range(0, 12, 2))
    return value


def get_all_macs() -> List[str]:
    macs: List[str] = []
    try:
        for addresses in psutil.net_if_addrs().values():
            for addr in addresses:
                family = getattr(addr, "family", None)
                if str(family).endswith("AF_LINK") or (hasattr(psutil, "AF_LINK") and family == psutil.AF_LINK):
                    mac = norm_mac(getattr(addr, "address", "") or "")
                    if mac and mac != "00:00:00:00:00:00":
                        macs.append(mac)
    except Exception:
        pass
    try:
        hw = uuid.getnode()
        if (hw >> 40) % 2 == 0:
            macs.append(norm_mac(f"{hw:012x}"))
    except Exception:
        pass
    seen: set[str] = set()
    ordered: List[str] = []
    for mac in macs:
        if mac and mac not in seen:
            seen.add(mac)
            ordered.append(mac)
    return ordered


def get_primary_mac(primary_ip: str, macs: List[str]) -> Optional[str]:
    try:
        for addresses in psutil.net_if_addrs().values():
            ips = [addr.address for addr in addresses if getattr(addr, "family", None) == socket.AF_INET]
            if primary_ip in ips:
                for addr in addresses:
                    family = getattr(addr, "family", None)
                    if str(family).endswith("AF_LINK") or (hasattr(psutil, "AF_LINK") and family == psutil.AF_LINK):
                        mac = norm_mac(getattr(addr, "address", "") or "")
                        if mac and mac in macs:
                            return mac
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
        freq = psutil.cpu_freq()
        if freq:
            info["freq_mhz"] = int(freq.current)
    except Exception:
        pass
    return info


def get_ram_gb() -> float:
    try:
        return round(psutil.virtual_memory().total / (1024 ** 3), 2)
    except Exception:
        return 0.0


def get_system_model() -> Dict[str, str]:
    result = {"manufacturer": "", "product_name": ""}
    if winreg is None:
        return result
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
            result["manufacturer"] = winreg.QueryValueEx(key, "SystemManufacturer")[0]
            result["product_name"] = winreg.QueryValueEx(key, "SystemProductName")[0]
    except Exception:
        pass
    return result


def screen_size() -> Tuple[int, int]:
    try:
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            return int(monitor["width"]), int(monitor["height"])
    except Exception:
        try:
            size = pyautogui.size()
            return int(size.width), int(size.height)
        except Exception:
            return 1280, 720


def scale_to_screen(x: float, y: float, w: float, h: float, sw: int, sh: int) -> Tuple[int, int]:
    if w <= 0 or h <= 0:
        return int(x), int(y)
    return int(x * sw / w), int(y * sh / h)


async def stream_frames(ws: WebSocketClientProtocol, cfg: AdaptiveConfig) -> None:
    try:
        minimum_interval = 1.0 / cfg.max_fps
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            cfg.screen_w = int(monitor["width"])
            cfg.screen_h = int(monitor["height"])
            logging.info("Streaming monitor %sx%s", cfg.screen_w, cfg.screen_h)
            while not STOP_EVENT.is_set():
                if _ws_is_closed(ws):
                    break
                if PAUSE_EVENT.is_set():
                    await asyncio.sleep(0.25)
                    continue

                loop_start = time.perf_counter()
                pil = _capture_with_fallback(sct, monitor)
                if pil is None:
                    await asyncio.sleep(0.5)
                    continue

                if cfg.scale < 0.999:
                    target_w = max(1, int(pil.width * cfg.scale))
                    target_h = max(1, int(pil.height * cfg.scale))
                    try:
                        pil = pil.resize((target_w, target_h), Image.BILINEAR)
                    except Exception:
                        pass

                buf = io.BytesIO()
                try:
                    pil.save(buf, format="JPEG", quality=int(cfg.quality), optimize=True, subsampling=cfg.subsampling)
                except Exception:
                    buf = io.BytesIO()
                    pil.save(buf, format="JPEG", quality=int(cfg.quality))
                payload = buf.getvalue()

                sent_at = time.perf_counter()
                try:
                    await ws.send(payload)
                except Exception:
                    break
                send_ms = (time.perf_counter() - sent_at) * 1000.0
                cfg.note_send(send_ms, len(payload))
                cfg.maybe_adapt()

                interval = max(minimum_interval, 1.0 / max(cfg.min_fps, cfg.effective_fps()))
                elapsed = time.perf_counter() - loop_start
                await asyncio.sleep(max(0.0, interval - elapsed))
    except asyncio.CancelledError:
        pass
    except Exception:
        logging.exception("stream_frames error")
    finally:
        logging.info("stream_frames finished")

async def _keepalive(ws: WebSocketClientProtocol) -> None:
    try:
        while not STOP_EVENT.is_set():
            await asyncio.sleep(25)
            if _ws_is_closed(ws):
                break
            try:
                await ws.ping()
            except Exception:
                break
    except asyncio.CancelledError:
        pass
    except Exception:
        logging.debug("keepalive ping failed", exc_info=True)
    finally:
        logging.debug("keepalive finished")

async def _heartbeat(ws: WebSocketClientProtocol) -> None:
    try:
        while not STOP_EVENT.is_set():
            await asyncio.sleep(15)
            if _ws_is_closed(ws):
                break
            try:
                await ws.send("HB")
            except Exception:
                break
    except asyncio.CancelledError:
        pass
    except Exception:
        logging.debug("heartbeat failed", exc_info=True)
    finally:
        logging.debug("heartbeat finished")

def key_map(key: str) -> str:
    mapping = {
        "Escape": "esc",
        "Enter": "enter",
        "Backspace": "backspace",
        "Tab": "tab",
        "Shift": "shift",
        "Control": "ctrl",
        "Alt": "alt",
        "Meta": "win",
        "ArrowLeft": "left",
        "ArrowRight": "right",
        "ArrowUp": "up",
        "ArrowDown": "down",
        "Delete": "delete",
        "Home": "home",
        "End": "end",
        "PageUp": "pageup",
        "PageDown": "pagedown",
        " ": "space",
    }
    if len(key) == 1:
        return key.lower()
    return mapping.get(key, key.lower())


async def handle_inputs(ws: WebSocketClientProtocol, cfg: AdaptiveConfig) -> None:
    screen_w, screen_h = screen_size()
    uploads: Dict[str, Dict[str, Any]] = {}

    def b64d(data: str) -> bytes:
        return base64.b64decode(data.encode("utf-8"))

    def b64e(data: bytes) -> str:
        return base64.b64encode(data).decode("utf-8")

    async def send_json(payload: Dict[str, Any]) -> None:
        try:
            if not _ws_is_closed(ws):
                await ws.send(json.dumps(payload, ensure_ascii=False))
        except Exception:
            pass

    def list_drives_full() -> List[Dict[str, Any]]:
        if platform.system().lower() == "windows":
            return list_drives()
        # *nix: смонтированные корни можно упростить до "/"
        return [{"path": "/", "label": "/"}]

    def list_directory_adv(path: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Возвращает (нормализованный путь, элементы).
        Элемент: {name,is_dir,size,mtime,full_path}
        """
        safe = _is_allowed_path(path) if path else None
        if not safe:
            # Если не задано — берём первый диск
            if platform.system().lower() == "windows":
                # Вернём пустой, клиент затем запросит диск
                return "", []
            else:
                safe = "/"
        p = Path(safe)
        if not p.exists() or not p.is_dir():
            raise FileNotFoundError(f"Путь недоступен: {safe}")
        items: List[Dict[str, Any]] = []
        with os.scandir(p) as it:
            for entry in it:
                try:
                    st = entry.stat()
                    items.append({
                        "name": entry.name,
                        "is_dir": entry.is_dir(),
                        "size": 0 if entry.is_dir() else int(st.st_size),
                        "mtime": int(st.st_mtime),
                        "full_path": str(Path(p) / entry.name)
                    })
                except Exception:
                    pass
        items.sort(key=lambda r: (not r["is_dir"], r["name"].lower()))
        return str(p), items
    
    async def op_mkdir(base: str, name: str):
        safe_base = _is_allowed_path(base)
        if not safe_base:
            raise PermissionError("Базовый путь запрещён")
        if not _valid_filename(name):
            raise ValueError("Недопустимое имя папки")
        target = Path(safe_base) / name
        target_parent = _is_allowed_path(str(target.parent))
        if not target_parent:
            raise PermissionError("Родительский путь запрещён")
        target.mkdir(parents=True, exist_ok=True)
        return str(target)

    async def op_rename(old_full: str, new_name: str):
        safe_old = _is_allowed_path(old_full)
        if not safe_old:
            raise PermissionError("Путь запрещён")
        if not _valid_filename(new_name):
            raise ValueError("Недопустимое имя")
        old_path = Path(safe_old)
        new_full = old_path.parent / new_name
        safe_new_parent = _is_allowed_path(str(new_full.parent))
        if not safe_new_parent:
            raise PermissionError("Родительский путь запрещён")
        old_path.rename(new_full)
        return str(old_path), str(new_full)

    def _rm_any(p: Path):
        if p.is_dir():
            for sub in p.iterdir():
                _rm_any(sub)
            p.rmdir()
        else:
            p.unlink(missing_ok=True)

    async def op_delete(paths: List[str]) -> Tuple[int, List[Dict[str, str]]]:
        ok = 0
        errors: List[Dict[str, str]] = []
        for raw in paths:
            safe = _is_allowed_path(raw)
            if not safe:
                errors.append({"path": raw, "err": "forbidden"})
                continue
            p = Path(safe)
            try:
                if p.exists():
                    _rm_any(p)
                ok += 1
            except Exception as e:
                errors.append({"path": raw, "err": str(e)})
        return ok, errors

    def cleanup_upload(transfer_id: str, remove_tmp: bool = True) -> None:
        session = uploads.pop(transfer_id, None)
        if not session:
            return
        try:
            try:
                fh = session.get("fh")
                if fh:
                    fh.close()
            except Exception:
                pass
            if remove_tmp:
                tmp = session.get("tmp")
                if tmp and os.path.exists(tmp):
                    os.remove(tmp)
        except Exception:
            pass

    try:
        while not STOP_EVENT.is_set():
            if _ws_is_closed(ws):
                break
            try:
                message = await ws.recv()
            except websockets.ConnectionClosed:
                break
            except Exception:
                await asyncio.sleep(0.1)
                continue

            now = time.time()
            for transfer_id, session in list(uploads.items()):
                if now - session.get("last_ts", now) > UPLOAD_IDLE_TIMEOUT:
                    cleanup_upload(transfer_id, remove_tmp=True)
                    await send_json({
                        "type": "file_error",
                        "transfer_id": transfer_id,
                        "message": "Загрузка отменена по таймауту",
                    })

            if not isinstance(message, str):
                continue

            try:
                data = json.loads(message)
            except Exception:
                continue

            msg_type = data.get("type")

            # --- НОВЫЕ ТИПЫ ДЛЯ ФАЙЛОВОГО МЕНЕДЖЕРА ---
            if msg_type == "file_drives":
                try:
                    await send_json({"type": "file_drives_result", "drives": list_drives_full()})
                except Exception as e:
                    await send_json({"type":"file_error","message":f"drives: {e}"})
                continue

            if msg_type == "file_list_adv":
                try:
                    path = str(data.get("path") or "")
                    cur, items = list_directory_adv(path)
                    await send_json({"type":"file_list_adv_result","path":cur,"items":items})
                except Exception as e:
                    await send_json({"type":"file_error","message":f"list: {e}"})
                continue

            if msg_type == "file_mkdir":
                try:
                    base = str(data.get("path") or "")
                    name = str(data.get("name") or "NewFolder")
                    created = await op_mkdir(base, name)
                    await send_json({"type":"file_mkdir_result","path":created})
                except Exception as e:
                    await send_json({"type":"file_error","message":f"mkdir: {e}"})
                continue

            if msg_type == "file_rename":
                try:
                    old_full = str(data.get("path") or "")
                    new_name = str(data.get("new_name") or "")
                    old_p, new_p = await op_rename(old_full, new_name)
                    await send_json({"type":"file_rename_result","old":old_p,"new":new_p})
                except Exception as e:
                    await send_json({"type":"file_error","message":f"rename: {e}"})
                continue

            if msg_type == "file_delete":
                try:
                    paths = data.get("paths") or []
                    ok, errs = await op_delete([str(p) for p in paths])
                    if errs:
                        await send_json({"type":"file_error","message":"delete partial","details":errs})
                    await send_json({"type":"file_delete_result","deleted":ok})
                except Exception as e:
                    await send_json({"type":"file_error","message":f"delete: {e}"})
                continue

            if msg_type == "net_ping":
                await send_json({"type": "net_pong", "ts": data.get("ts")})
                continue

            if msg_type == "viewer_info":
                viewport = data.get("viewport") or {}
                cfg.fit_to_viewport(int(viewport.get("w", 0)), int(viewport.get("h", 0)), float(viewport.get("dpr", 1.0)))
                continue

            if msg_type == "viewer_stats":
                rx_bps = float(data.get("rx_bps") or 0.0)
                if rx_bps > 0:
                    cfg.target_bps = rx_bps * 0.85
                continue

            if msg_type == "stream_set":
                if "fps" in data:
                    cfg.fps = float(data["fps"])
                if "quality" in data:
                    cfg.quality = int(data["quality"])
                if "scale" in data:
                    cfg.scale = float(data["scale"])
                continue

            if msg_type == "mouse":
                cfg.on_input()
                x = data.get("x", 0.0)
                y = data.get("y", 0.0)
                w = data.get("w", 1.0)
                h = data.get("h", 1.0)
                sx, sy = scale_to_screen(x, y, w, h, screen_w, screen_h)
                event = data.get("event")
                try:
                    if event == "move":
                        pyautogui.moveTo(sx, sy, duration=0)
                    elif event == "down":
                        button = "left" if data.get("button", 0) == 0 else ("middle" if data.get("button") == 1 else "right")
                        pyautogui.mouseDown(x=sx, y=sy, button=button)
                    elif event == "up":
                        button = "left" if data.get("button", 0) == 0 else ("middle" if data.get("button") == 1 else "right")
                        pyautogui.mouseUp(x=sx, y=sy, button=button)
                    elif event == "wheel":
                        delta = int(data.get("delta", 0))
                        pyautogui.scroll(-int(delta / 10), x=sx, y=sy)
                except Exception:
                    pass
                continue

            if msg_type == "key":
                cfg.on_input()
                key = key_map(str(data.get("key", "")))
                event = data.get("event")
                if key:
                    try:
                        if event == "down":
                            pyautogui.keyDown(key)
                        elif event == "up":
                            pyautogui.keyUp(key)
                    except Exception:
                        pass
                continue

            if msg_type == "file_list":
                path = str(data.get("path") or "")
                safe_path = _is_allowed_path(path)
                if not safe_path:
                    await send_json({"type": "file_error", "message": "Путь вне разрешённых директорий"})
                    continue
                try:
                    items: List[Dict[str, Any]] = []
                    with os.scandir(safe_path) as entries:
                        for entry in entries:
                            try:
                                info = entry.stat()
                                items.append(
                                    {
                                        "name": entry.name,
                                        "is_dir": entry.is_dir(),
                                        "size": int(info.st_size),
                                        "mtime": int(info.st_mtime),
                                    }
                                )
                            except Exception:
                                pass
                    items.sort(key=lambda item: (not item["is_dir"], item["name"].lower()))
                    await send_json({"type": "file_list_result", "path": safe_path, "items": items})
                except Exception as exc:
                    await send_json({"type": "file_error", "message": f"Листинг не удался: {exc}"})
                continue

            if msg_type == "file_upload_begin":
                transfer_id = str(data.get("transfer_id") or "")
                name = os.path.basename(str(data.get("name") or "upload.bin"))
                size = int(data.get("size") or 0)
                dest_dir = str(data.get("dest_dir") or DEFAULT_UPLOAD_DIR)
                final_path = _safe_join(dest_dir, name)
                if not final_path:
                    await send_json(
                        {
                            "type": "file_error",
                            "message": "Недопустимое имя или директория вне белого списка",
                            "transfer_id": transfer_id,
                        }
                    )
                    continue
                try:
                    os.makedirs(os.path.dirname(final_path), exist_ok=True)
                    tmp_path = final_path + ".part"
                    fh = open(tmp_path, "wb")
                    uploads[transfer_id] = {
                        "fh": fh,
                        "tmp": tmp_path,
                        "final": final_path,
                        "size": size,
                        "written": 0,
                        "last_ts": time.time(),
                    }
                    await send_json({"type": "file_upload_ack", "transfer_id": transfer_id, "path": final_path})
                except Exception as exc:
                    await send_json({"type": "file_error", "message": f"Не удалось открыть файл для записи: {exc}", "transfer_id": transfer_id})
                continue

            if msg_type == "file_upload_chunk":
                transfer_id = str(data.get("transfer_id") or "")
                session = uploads.get(transfer_id)
                if not session:
                    await send_json({"type": "file_error", "message": "Неизвестная сессия загрузки", "transfer_id": transfer_id})
                    continue
                try:
                    data_bytes = b64d(str(data.get("data_b64") or ""))
                    session["fh"].write(data_bytes)
                    session["written"] += len(data_bytes)
                    session["last_ts"] = time.time()
                except Exception as exc:
                    await send_json({"type": "file_error", "message": f"Ошибка записи: {exc}", "transfer_id": transfer_id})
                continue

            if msg_type == "file_upload_end":
                transfer_id = str(data.get("transfer_id") or "")
                session = uploads.pop(transfer_id, None)
                if session:
                    try:
                        session["fh"].close()
                    except Exception:
                        pass
                    try:
                        os.replace(session["tmp"], session["final"])
                        await send_json({"type": "file_upload_done", "transfer_id": transfer_id, "path": session.get("final")})
                    except Exception as exc:
                        try:
                            if os.path.exists(session["tmp"]):
                                os.remove(session["tmp"])
                        except Exception:
                            pass
                        await send_json({"type": "file_error", "message": f"Завершение загрузки не удалось: {exc}", "transfer_id": transfer_id})
                continue

            if msg_type == "file_upload_cancel":
                transfer_id = str(data.get("transfer_id") or "")
                cleanup_upload(transfer_id, remove_tmp=True)
                await send_json({"type": "file_error", "transfer_id": transfer_id, "message": "Загрузка отменена пользователем"})
                continue

            if msg_type == "file_download_begin":
                transfer_id = str(data.get("transfer_id") or "")
                path = str(data.get("path") or "")
                safe_path = _is_allowed_path(path)
                if not safe_path:
                    await send_json({"type": "file_error", "message": "Путь вне разрешённых директорий", "transfer_id": transfer_id})
                    continue
                name = os.path.basename(safe_path) or "download.bin"
                try:
                    size = os.path.getsize(safe_path)
                    await send_json({"type": "file_download_meta", "transfer_id": transfer_id, "name": name, "size": int(size)})
                    with open(safe_path, "rb") as fh:
                        chunk = fh.read(64 * 1024)
                        while chunk:
                            await send_json({"type": "file_download_chunk", "transfer_id": transfer_id, "data_b64": b64e(chunk)})
                            chunk = fh.read(64 * 1024)
                    await send_json({"type": "file_download_end", "transfer_id": transfer_id})
                except Exception as exc:
                    await send_json({"type": "file_error", "message": f"Скачивание не удалось: {exc}", "transfer_id": transfer_id})
                continue

            # --- ДОПОЛНИТЕЛЬНЫЕ ОПЕРАЦИИ ---

            if msg_type == "file_paste":
                try:
                    dest = str(data.get("dest") or "")
                    entries = data.get("entries") or []
                    safe_dest = _is_allowed_path(dest)
                    if not safe_dest:
                        raise PermissionError("dest forbidden")
                    dest_p = Path(safe_dest)
                    if not dest_p.exists():
                        raise FileNotFoundError("dest not exists")
                    results = []
                    for ent in entries:
                        src = str(ent.get("src") or "")
                        op = ent.get("op") or "copy"
                        safe_src = _is_allowed_path(src)
                        if not safe_src:
                            results.append({"src": src, "status":"error", "err":"src forbidden"})
                            continue
                        src_p = Path(safe_src)
                        if not src_p.exists():
                            results.append({"src": src, "status":"error", "err":"not found"})
                            continue
                        try:
                            target = dest_p / src_p.name
                            if target.exists():
                                # стратегия: авто-суффикс
                                stem = src_p.stem
                                suf = src_p.suffix
                                k=1
                                while target.exists() and k<1000:
                                    target = dest_p / f"{stem} ({k}){suf}"
                                    k+=1
                            if op == "move":
                                shutil.move(str(src_p), str(target))
                            else:
                                if src_p.is_dir():
                                    shutil.copytree(src_p, target)
                                else:
                                    shutil.copy2(src_p, target)
                            results.append({"src": src, "status":"ok", "dst": str(target)})
                        except Exception as e:
                            results.append({"src": src, "status":"error", "err": str(e)})
                    await send_json({"type":"file_paste_result","dest":safe_dest,"results":results})
                except Exception as e:
                    await send_json({"type":"file_error","message":f"paste: {e}"})
                continue

            if msg_type == "file_zip_download":
                try:
                    paths = data.get("paths") or []
                    transfer_id = str(data.get("transfer_id") or "")
                    tmp_dir = Path(os.environ.get("TEMP") or Path.home())
                    zip_path = tmp_dir / f"rpcs_{transfer_id or int(time.time())}.zip"
                    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                        for raw in paths:
                            safe = _is_allowed_path(str(raw))
                            if not safe: 
                                continue
                            p = Path(safe)
                            if p.is_dir():
                                for root, dirs, files in os.walk(p):
                                    for f in files:
                                        fp = Path(root) / f
                                        rel = fp.relative_to(p.parent)
                                        try:
                                            zf.write(fp, arcname=rel.as_posix())
                                        except Exception:
                                            pass
                            else:
                                rel = p.name
                                try:
                                    zf.write(p, arcname=rel)
                                except Exception:
                                    pass
                    size = zip_path.stat().st_size
                    # поток как обычное скачивание
                    await send_json({"type":"file_download_meta","transfer_id":transfer_id,"name":zip_path.name,"size":int(size)})
                    with open(zip_path,"rb") as fh:
                        chunk = fh.read(64*1024)
                        while chunk:
                            await send_json({"type":"file_download_chunk","transfer_id":transfer_id,"data_b64":b64e(chunk)})
                            chunk = fh.read(64*1024)
                    await send_json({"type":"file_download_end","transfer_id":transfer_id})
                    try:
                        os.remove(zip_path)
                    except Exception:
                        pass
                except Exception as e:
                    await send_json({"type":"file_error","message":f"zip: {e}"} )
                continue

            if msg_type == "file_preview":
                try:
                    path = str(data.get("path") or "")
                    safe = _is_allowed_path(path)
                    if not safe:
                        raise PermissionError("forbidden")
                    size = os.path.getsize(safe)
                    if size > PREVIEW_MAX_SIZE:
                        raise ValueError("too large")
                    mime, _ = mimetypes.guess_type(safe)
                    mime = mime or ""
                    kind = "binary"
                    payload: Dict[str, Any] = {}
                    if mime.startswith("text") or safe.lower().endswith((".log",".md",".txt",".json",".py",".cfg",".ini",".yaml",".yml",".bat",".ps1")):
                        kind="text"
                        with open(safe,"r",encoding="utf-8",errors="replace") as fh:
                            payload["text"]=fh.read(PREVIEW_MAX_SIZE)
                    elif mime.startswith("image"):
                        kind="image"
                        with open(safe,"rb") as fh:
                            payload["data_b64"]=b64e(fh.read())
                            payload["mime"]=mime
                    else:
                        # попытка как текст
                        try:
                            with open(safe,"r",encoding="utf-8",errors="strict") as fh:
                                t = fh.read(PREVIEW_MAX_SIZE)
                                kind="text"
                                payload["text"]=t
                        except Exception:
                            kind="binary"
                    await send_json({"type":"file_preview_result","path":safe,"kind":kind,**payload})
                except Exception as e:
                    await send_json({"type":"file_error","message":f"preview: {e}"})
                continue

            if msg_type == "file_search":
                try:
                    root = str(data.get("path") or "")
                    query = str(data.get("query") or "").strip()
                    depth = int(data.get("depth") or SEARCH_DEFAULT_DEPTH)
                    max_items = int(data.get("max") or SEARCH_MAX_RESULTS)
                    if not query:
                        raise ValueError("empty query")
                    safe_root = _is_allowed_path(root)
                    if not safe_root:
                        raise PermissionError("root forbidden")
                    root_p = Path(safe_root)
                    results = []
                    qlow = query.lower()
                    def walk(p: Path, d: int):
                        if len(results)>=max_items: return
                        if d<0: return
                        try:
                            for entry in p.iterdir():
                                name = entry.name
                                if qlow in name.lower():
                                    st = entry.stat()
                                    results.append({
                                        "name": name,
                                        "is_dir": entry.is_dir(),
                                        "size": 0 if entry.is_dir() else int(st.st_size),
                                        "mtime": int(st.st_mtime),
                                        "full_path": str(entry)
                                    })
                                    if len(results)>=max_items: return
                                if entry.is_dir():
                                    walk(entry, d-1)
                                    if len(results)>=max_items: return
                        except Exception:
                            pass
                    walk(root_p, depth)
                    await send_json({"type":"file_search_result","path":safe_root,"query":query,"items":results})
                except Exception as e:
                    await send_json({"type":"file_error","message":f"search: {e}"})
                continue
    except asyncio.CancelledError:
        pass
    except Exception:
        logging.exception("handle_inputs error")
    finally:
        for transfer_id in list(uploads.keys()):
            cleanup_upload(transfer_id, remove_tmp=True)
        logging.info("handle_inputs finished")


def build_hello_payload(agent_id: str) -> Dict[str, Any]:
    host = get_hostname()
    ip = get_primary_ip()
    ips = get_all_ips()
    macs = get_all_macs()
    width, height = screen_size()
    ts = int(time.time())
    nonce = secrets.token_hex(16)
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
            "system_model": get_system_model(),
        },
        "screen": {"width": width, "height": height},
        "time": _safe_now_iso(),
        "auth": {
            "ts": ts,
            "nonce": nonce,
            "sig": _sign_hello(agent_id, ts, nonce),
        },
    }
    return payload


async def connect_once(agent_id: str, uri: str) -> bool:
    try:
        parsed = urlparse(uri)
        if parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
            logging.warning("AGENT_SERVER указывает на loopback (%s). Убедитесь, что сервер доступен удалённо.", parsed.hostname)

        ssl_ctx = _ssl_context_for(uri)
        async with websockets.connect(
            uri,
            open_timeout=15,
            close_timeout=10,
            ping_interval=15,
            ping_timeout=15,
            max_queue=None,
            max_size=10 * 1024 * 1024,
            ssl=ssl_ctx,
        ) as ws:
            hello = build_hello_payload(agent_id)
            await ws.send(json.dumps(hello, ensure_ascii=False))
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=10)
            except asyncio.TimeoutError:
                logging.warning("Handshake timeout")
                return False
            if isinstance(resp, (bytes, bytearray)):
                try:
                    resp = resp.decode("utf-8", "ignore")
                except Exception:
                    resp = ""
            if str(resp).strip().upper() != "OK":
                logging.warning("Handshake failed: %s", resp)
                return False
            logging.info("Handshake OK with %s", uri)

            cfg = AdaptiveConfig(*screen_size())
            frame_task = asyncio.create_task(stream_frames(ws, cfg), name="stream_frames")
            input_task = asyncio.create_task(handle_inputs(ws, cfg), name="handle_inputs")
            keepalive_task = asyncio.create_task(_keepalive(ws), name="ws_keepalive")
            heartbeat_task = asyncio.create_task(_heartbeat(ws), name="ws_heartbeat")
            wait_closed = asyncio.create_task(ws.wait_closed(), name="ws_wait_closed")

            done, pending = await asyncio.wait(
                {frame_task, input_task, keepalive_task, heartbeat_task, wait_closed},
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()
            for task in pending:
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            for task in done:
                try:
                    exc = task.exception()
                    if exc:
                        logging.error("Task %s failed: %s", task.get_name(), exc)
                except asyncio.CancelledError:
                    pass

            logging.info("WebSocket closed: code=%s reason=%s", getattr(ws, "close_code", None), getattr(ws, "close_reason", ""))
            return True
    except ws_exceptions.InvalidMessage:
        if uri.startswith("ws://"):
            alt = "wss://" + uri[len("ws://") :]
            logging.warning("InvalidMessage на %s; пробуем %s", uri, alt)
            return await connect_once(agent_id, alt)
        logging.exception("connect_once InvalidMessage")
        return False
    except ssl.SSLCertVerificationError:
        logging.error("Проверка TLS не пройдена. Установите AGENT_TLS_INSECURE=1 или задайте AGENT_CA_FILE.")
        return False
    except (ConnectionRefusedError, socket.gaierror, OSError) as exc:
        logging.warning("Endpoint %s недоступен: %s", uri, exc)
        raise ImmediateRetry from exc
    except ImmediateRetry:
        raise
    except asyncio.CancelledError:
        raise
    except Exception:
        logging.exception("connect_once error")
        return False



def _is_allowed_path(path: str) -> Optional[str]:
    """
    Расширено: если FULL_FS_MODE=1 (по умолчанию) и путь на локальном диске, разрешаем.
    Иначе используем белый список ALLOWED_ROOTS.
    """
    try:
        candidate = Path(path).expanduser()
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            # для операций mkdir/rename может не существовать пока
            resolved = candidate.resolve(strict=False)
    except Exception:
        return None

    if FULL_FS_MODE:
        # Простейшая фильтрация: запрещаем UNC и относительные
        p_str = str(resolved)
        if platform.system().lower() == "windows":
            # Разрешаем X:\... или X:\
            if len(p_str) >= 2 and p_str[1] == ":":
                return p_str
        else:
            # На *nix разрешаем всё под /
            if p_str.startswith("/"):
                return p_str

    # Строгий режим (старый)
    for root in ALLOWED_ROOTS:
        try:
            root_resolved = root.expanduser()
            try:
                root_resolved = root_resolved.resolve(strict=True)
            except FileNotFoundError:
                root_resolved = root_resolved.resolve(strict=False)
        except Exception:
            continue
        candidate_str = str(resolved).lower()
        root_str = str(root_resolved).lower()
        if candidate_str == root_str or candidate_str.startswith(root_str.rstrip(os.sep) + os.sep):
            return str(resolved)
    return None


def _valid_filename(name: str) -> bool:
    return bool(name) and not any(ch in INVALID_NAME_CHARS for ch in name)


def _safe_join(dest_dir: str, name: str) -> Optional[str]:
    if not _valid_filename(name):
        return None
    base = _is_allowed_path(dest_dir)
    if not base:
        return None
    full = Path(base) / name
    return _is_allowed_path(str(full))


def _sign_hello(agent_id: str, ts: int, nonce: str) -> str:
    message = f"{agent_id}|{ts}|{nonce}".encode("utf-8")
    return hmac.new(SHARED_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()


async def main() -> None:
    set_background_priority()
    log_file = _setup_logging()
    logging.info("Лог: %s", log_file)
    uris, src = resolve_server_uris()
    logging.info("SERVER_URIS[%s]=%s", src, uris)
    if SHARED_SECRET == "rpcs_dev_secret_change_me":
        logging.warning("SHARED_SECRET имеет значение по умолчанию. Измените для продакшена.")
    if not is_admin():
        logging.info("Запуск без прав администратора. Управление может быть ограничено.")

    agent_id = load_id()
    logging.info("agent_id=%s", agent_id)

    tray_thread = threading.Thread(target=run_tray, args=(agent_id,), daemon=True)
    tray_thread.start()

    delay = 2.0
    while not STOP_EVENT.is_set():
        success = False
        immediate_retry = False
        for uri in uris:
            if STOP_EVENT.is_set():
                break
            try:
                logging.info("Connecting to %s", uri)
                connected = await connect_once(agent_id, uri)
                logging.info("Session finished (success=%s, uri=%s)", connected, uri)
                if connected:
                    success = True
            except ImmediateRetry:
                logging.debug("Immediate retry requested for %s", uri)
                immediate_retry = True
                continue
            except Exception:
                logging.exception("connect_once exception")
            if STOP_EVENT.is_set():
                break
        if STOP_EVENT.is_set():
            break
        if success:
            await asyncio.sleep(2.0)
            delay = 2.0
        elif immediate_retry:
            await asyncio.sleep(2.0)
            delay = 2.0
        else:
            await asyncio.sleep(delay)
            delay = min(30.0, delay * 1.5)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        STOP_EVENT.set()