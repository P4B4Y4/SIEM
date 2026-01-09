import os
import sys
import time
import subprocess
import threading
from datetime import datetime, timedelta
import io

import re
 
try:
    import importlib.resources as _resources
except Exception:
    _resources = None

import pystray
from pystray import MenuItem as Item
from PIL import Image

try:
    from win10toast import ToastNotifier
except Exception:
    ToastNotifier = None


APP_NAME = "JFS VPN"
TUNNEL_NAME = "JFSVPN"
CONFIG_PATH = r"C:\ProgramData\JFSVPN\jfs.conf"
WIREGUARD_EXE = r"C:\Program Files\WireGuard\wireguard.exe"

LOG_PATH = r"C:\ProgramData\JFSVPN\tray.log"
BRAND_BG = (0, 0, 128, 255)
PROGRAMDATA_DIR = r"C:\ProgramData\JFSVPN"

CHECK_INTERVAL_SECONDS = 10
ALERT_REPEAT_MINUTES = 5

KILLSWITCH_RULE_PREFIX = "JFSVPN_KILLSWITCH"


def _run(cmd, timeout=20):
    creationflags = 0
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        creationflags = subprocess.CREATE_NO_WINDOW
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=creationflags,
    )


def _service_name():
    return f"WireGuardTunnel${TUNNEL_NAME}"


def _wireguard_installed():
    return os.path.exists(WIREGUARD_EXE)


def _config_present():
    return os.path.exists(CONFIG_PATH)


def _parse_wg_endpoint(conf_path: str):
    try:
        with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Endpoint = host:port
        m = re.search(r"^\s*Endpoint\s*=\s*([^\s:#\]]+)(?::(\d+))?\s*$", content, re.MULTILINE)
        if not m:
            return None, None
        host = (m.group(1) or "").strip()
        port = (m.group(2) or "").strip() or "51820"
        return host, port
    except Exception:
        return None, None


def _killswitch_set(enable: bool):
    try:
        if not enable:
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={KILLSWITCH_RULE_PREFIX}_BLOCK_ALL"], timeout=30)
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={KILLSWITCH_RULE_PREFIX}_ALLOW_WG"], timeout=30)
            return True

        ip, port = _parse_wg_endpoint(CONFIG_PATH)
        if not ip:
            return False

        # Allow WireGuard server UDP port
        _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={KILLSWITCH_RULE_PREFIX}_ALLOW_WG",
                "dir=out",
                "action=allow",
                "protocol=UDP",
                f"remoteip={ip}",
                f"remoteport={port}",
                "profile=any",
            ],
            timeout=30,
        )

        # Block all other outbound
        _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={KILLSWITCH_RULE_PREFIX}_BLOCK_ALL",
                "dir=out",
                "action=block",
                "protocol=any",
                "remoteip=any",
                "profile=any",
            ],
            timeout=30,
        )
        return True
    except Exception:
        return False


def is_connected():
    try:
        # sc query returns RUNNING/STOPPED
        res = _run(["sc", "query", _service_name()], timeout=10)
        out = (res.stdout or "") + (res.stderr or "")
        return "STATE" in out and "RUNNING" in out
    except Exception:
        return False


def connect():
    # Start tunnel service
    return _run(["net", "start", _service_name()], timeout=30)


def disconnect():
    # Stop tunnel service
    return _run(["net", "stop", _service_name()], timeout=30)


def notify(title, message):
    if ToastNotifier is None:
        return
    try:
        ToastNotifier().show_toast(title, message, duration=5, threaded=True)
    except Exception:
        pass


def _log(msg: str):
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} {msg}\n")
    except Exception:
        pass


class TrayApp:
    def __init__(self):
        self.icon = None
        self._stop = threading.Event()
        self._last_alert = None
        self._last_state = None
        self._manual_disconnect = False

    def _load_icon(self):
        base = os.path.dirname(os.path.abspath(sys.argv[0]))
        programdata_dir = PROGRAMDATA_DIR

        # Prefer ProgramData first (most reliable path, avoids _MEIPASS permission issues)
        for name in ("jfs_logo.png", "jfs_logo.ico", "logo.png", "logo.ico", "icon.png", "icon.ico"):
            for candidate in (os.path.join(programdata_dir, name), os.path.join(base, name)):
                if os.path.exists(candidate):
                    try:
                        img = Image.open(candidate)
                        img = img.convert("RGBA")
                        img = img.resize((64, 64), Image.LANCZOS)
                        try:
                            a = img.getchannel("A")
                            mn, mx = a.getextrema()
                        except Exception:
                            mn, mx = (None, None)

                        # Only composite onto navy if the image is effectively invisible.
                        if mx == 0:
                            bg = Image.new("RGBA", img.size, BRAND_BG)
                            img = Image.alpha_composite(bg, img)

                        _log(f"icon=external:{candidate} mode={img.mode} size={img.size} alpha=({mn},{mx})")
                        return img
                    except Exception:
                        _log(f"icon=external_failed:{candidate}")
                        pass

        # Fallback: generate a simple branded icon (never transparent)
        try:
            img = Image.new("RGBA", (64, 64), BRAND_BG)
            _log("icon=generated")
            return img
        except Exception:
            pass

        # Fallback: empty image
        _log(f"icon=fallback base={base} programdata={programdata_dir}")
        return Image.new("RGBA", (64, 64), (0, 0, 0, 0))

    def _status_text(self):
        if not _wireguard_installed():
            return "WireGuard not installed"
        if not _config_present():
            return "Config missing"
        return "Connected" if is_connected() else "Disconnected"

    def _menu(self):
        def _connect(_icon, _item):
            self._manual_disconnect = False
            # Re-enable kill-switch before connecting
            _killswitch_set(True)
            connect()

        def _disconnect(_icon, _item):
            # Manual disconnect: allow fallback internet by removing kill-switch rules
            self._manual_disconnect = True
            disconnect()
            _killswitch_set(False)

        return pystray.Menu(
            Item("Connect", _connect, enabled=lambda item: not is_connected()),
            Item("Disconnect", _disconnect, enabled=lambda item: is_connected()),
            Item(lambda item: f"Status: {self._status_text()}", None, enabled=False),
        )

    def _update_tooltip_and_icon(self):
        status = self._status_text()
        if self.icon:
            self.icon.title = f"{APP_NAME} - {status}"

    def _monitor_loop(self):
        while not self._stop.is_set():
            try:
                state = is_connected()
                if self._last_state is None:
                    self._last_state = state

                if state != self._last_state:
                    self._last_state = state
                    if not state:
                        self._last_alert = None
                        notify(APP_NAME, "VPN disconnected. Click tray icon to reconnect.")

                # Auto-reconnect when disconnected unless user manually disconnected
                if not state and not self._manual_disconnect and _wireguard_installed() and _config_present():
                    # Ensure kill-switch stays enabled while we auto-reconnect
                    _killswitch_set(True)
                    connect()

                # Periodic alert while disconnected
                if not state:
                    now = datetime.now()
                    if self._last_alert is None or (now - self._last_alert) >= timedelta(minutes=ALERT_REPEAT_MINUTES):
                        self._last_alert = now
                        notify(APP_NAME, "VPN is not connected.")

                self._update_tooltip_and_icon()
            except Exception:
                pass

            time.sleep(CHECK_INTERVAL_SECONDS)

    def run(self):
        image = self._load_icon()
        self.icon = pystray.Icon(APP_NAME, image, title=APP_NAME, menu=self._menu())

        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()

        self.icon.run()


def main():
    TrayApp().run()


if __name__ == "__main__":
    main()
