from cx_Freeze import setup, Executable
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
AGENT_SCRIPT = str(ROOT / "agent" / "agent.py")

build_exe_options = {
    "includes": [
        # stdlib
        "http", "asyncio", "logging", "json", "time", "io", "base64", "hmac", "hashlib", "secrets", "threading", "socket", "platform", "uuid", "getpass", "ssl", "re",
        # third-party
        "websockets", "websockets.asyncio", "websockets.client",
        "PIL", "PIL.Image",
        "mss",
        "pyautogui", "psutil",
        "pystray", "pystray._win32",
        "pyscreeze", "pytweening", "pymsgbox", "mouseinfo", "pygetwindow", "pyperclip", "pyrect",
        "win32api", "win32con", "win32gui",
    ],
    "excludes": [
        "tkinter", "pytest", "unittest", "distutils"
    ],
    "include_msvcr": True,
    "optimize": 2,
    "zip_include_packages": ["*"],
    "zip_exclude_packages": [],
}

base = "Win32GUI" if sys.platform == "win32" else None

executables = [
    Executable(
        script="agent\\agent.py",
        target_name="rpc-agent.exe",
        base=base  # без консоли в Windows
    )
]

setup(
    name="rpc-agent",
    version="0.1.0",
    description="Remote PC Control Agent",
    options={"build_exe": build_exe_options},
    executables=executables
)