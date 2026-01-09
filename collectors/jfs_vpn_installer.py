import os
import sys
import shutil
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox


APP_NAME = "JFS VPN Installer"
BRAND_COLOR = "#000080"
TEXT_COLOR = "#ffffff"
TUNNEL_NAME = "JFSVPN"
TARGET_DIR = r"C:\ProgramData\JFSVPN"
TARGET_CONFIG = os.path.join(TARGET_DIR, "jfs.conf")
WIREGUARD_EXE = r"C:\Program Files\WireGuard\wireguard.exe"


def _run(cmd, timeout=120):
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


def _is_admin():
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _ensure_admin():
    if _is_admin():
        return True

    try:
        import ctypes

        params = " ".join([f'"{a}"' for a in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return False
    except Exception:
        messagebox.showerror(APP_NAME, "Administrator privileges are required.")
        return False


def _wireguard_installed():
    return os.path.exists(WIREGUARD_EXE)


def _install_wireguard_msi(msi_path):
    # msiexec /i <msi> /qn
    res = _run(["msiexec", "/i", msi_path, "/qn", "/norestart"], timeout=600)
    return res


def _copy_config(src):
    os.makedirs(TARGET_DIR, exist_ok=True)
    shutil.copy2(src, TARGET_CONFIG)


def _install_tunnel_service():
    # wireguard.exe /installtunnelservice <conf>
    return _run([WIREGUARD_EXE, "/installtunnelservice", TARGET_CONFIG], timeout=60)


def _set_service_autostart():
    return _run(["sc", "config", _service_name(), "start=", "auto"], timeout=30)


def _start_service():
    return _run(["net", "start", _service_name()], timeout=30)


def _copy_tray_app(tray_exe_path, icon_path=None):
    # Place tray exe alongside config
    dst = os.path.join(TARGET_DIR, os.path.basename(tray_exe_path))
    shutil.copy2(tray_exe_path, dst)

    if icon_path:
        try:
            # Keep original extension for tray loader (supports .ico or .png)
            ext = os.path.splitext(icon_path)[1].lower() or ".ico"
            shutil.copy2(icon_path, os.path.join(TARGET_DIR, f"jfs_logo{ext}"))
        except Exception:
            pass

    return dst


def _add_run_registry(tray_exe_dst):
    # HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE,
        )
        winreg.SetValueEx(key, "JFSVPN", 0, winreg.REG_SZ, tray_exe_dst)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def _apply_killswitch(enable: bool, wg_server_ip: str, wg_server_port: str):
    # Basic kill-switch using Windows Firewall rules.
    # When enabled:
    # - Block outbound to Any
    # - Allow outbound to WireGuard server (UDP)
    # - Allow DHCP/DNS optionally (not added here)
    # Important: This is a simplified approach and may need tuning per environment.
    rule_prefix = "JFSVPN_KILLSWITCH"

    if not enable:
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_prefix}_BLOCK_ALL"], timeout=30)
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_prefix}_ALLOW_WG"], timeout=30)
        return

    # Allow WireGuard server UDP port
    _run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_prefix}_ALLOW_WG",
            "dir=out",
            "action=allow",
            "protocol=UDP",
            f"remoteip={wg_server_ip}",
            f"remoteport={wg_server_port}",
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
            f"name={rule_prefix}_BLOCK_ALL",
            "dir=out",
            "action=block",
            "protocol=any",
            "remoteip=any",
            "profile=any",
        ],
        timeout=30,
    )


class InstallerUI:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("620x360")

        self.root.configure(bg=BRAND_COLOR)

        self.msi_path = tk.StringVar(value="")
        self.conf_path = tk.StringVar(value="")
        self.tray_exe_path = tk.StringVar(value="")
        self.wg_server_ip = tk.StringVar(value="")
        self.wg_server_port = tk.StringVar(value="51820")
        self.enable_killswitch = tk.BooleanVar(value=True)

        frm = tk.Frame(root, padx=16, pady=16, bg=BRAND_COLOR)
        frm.pack(fill=tk.BOTH, expand=True)

        def _label(*args, **kwargs):
            kwargs.setdefault("bg", BRAND_COLOR)
            kwargs.setdefault("fg", TEXT_COLOR)
            return tk.Label(*args, **kwargs)

        def _button(*args, **kwargs):
            kwargs.setdefault("bg", BRAND_COLOR)
            kwargs.setdefault("fg", TEXT_COLOR)
            kwargs.setdefault("activebackground", BRAND_COLOR)
            kwargs.setdefault("activeforeground", TEXT_COLOR)
            kwargs.setdefault("relief", tk.RAISED)
            kwargs.setdefault("bd", 1)
            return tk.Button(*args, **kwargs)

        _label(frm, text="WireGuard MSI (for Windows)").grid(row=0, column=0, sticky="w")
        tk.Entry(frm, textvariable=self.msi_path, width=60).grid(row=1, column=0, sticky="we", pady=(4, 0))
        _button(frm, text="Browse", command=self.browse_msi).grid(row=1, column=1, padx=(8, 0))

        _label(frm, text="VPN Config (jfs.conf)").grid(row=2, column=0, sticky="w", pady=(12, 0))
        tk.Entry(frm, textvariable=self.conf_path, width=60).grid(row=3, column=0, sticky="we", pady=(4, 0))
        _button(frm, text="Browse", command=self.browse_conf).grid(row=3, column=1, padx=(8, 0))

        _label(frm, text="Tray App EXE (built jfs_vpn_tray.exe)").grid(row=4, column=0, sticky="w", pady=(12, 0))
        tk.Entry(frm, textvariable=self.tray_exe_path, width=60).grid(row=5, column=0, sticky="we", pady=(4, 0))
        _button(frm, text="Browse", command=self.browse_tray).grid(row=5, column=1, padx=(8, 0))

        tk.Checkbutton(frm, text="Enable kill-switch (block internet if VPN down)", variable=self.enable_killswitch, bg=BRAND_COLOR, fg=TEXT_COLOR, selectcolor=BRAND_COLOR, activebackground=BRAND_COLOR, activeforeground=TEXT_COLOR).grid(
            row=6, column=0, sticky="w", pady=(12, 0)
        )

        ipfrm = tk.Frame(frm, bg=BRAND_COLOR)
        ipfrm.grid(row=7, column=0, sticky="we", pady=(6, 0))
        _label(ipfrm, text="WG Server IP").grid(row=0, column=0, sticky="w")
        tk.Entry(ipfrm, textvariable=self.wg_server_ip, width=24).grid(row=0, column=1, padx=(8, 18))
        _label(ipfrm, text="WG UDP Port").grid(row=0, column=2, sticky="w")
        tk.Entry(ipfrm, textvariable=self.wg_server_port, width=10).grid(row=0, column=3, padx=(8, 0))

        _button(frm, text="Install", command=self.install).grid(row=8, column=0, sticky="w", pady=(18, 0))

        frm.columnconfigure(0, weight=1)

    def browse_msi(self):
        p = filedialog.askopenfilename(title="Select WireGuard MSI", filetypes=[("MSI", "*.msi"), ("All", "*.*")])
        if p:
            self.msi_path.set(p)

    def browse_conf(self):
        p = filedialog.askopenfilename(title="Select jfs.conf", filetypes=[("WireGuard Config", "*.conf"), ("All", "*.*")])
        if p:
            self.conf_path.set(p)

    def browse_tray(self):
        p = filedialog.askopenfilename(title="Select tray EXE", filetypes=[("EXE", "*.exe"), ("All", "*.*")])
        if p:
            self.tray_exe_path.set(p)

    def install(self):
        if not _ensure_admin():
            # Relaunch requested
            self.root.destroy()
            return

        if not self.conf_path.get() or not os.path.exists(self.conf_path.get()):
            messagebox.showerror(APP_NAME, "Please select a valid jfs.conf")
            return

        if not self.tray_exe_path.get() or not os.path.exists(self.tray_exe_path.get()):
            messagebox.showerror(APP_NAME, "Please select a valid tray EXE")
            return

        if not _wireguard_installed():
            if not self.msi_path.get() or not os.path.exists(self.msi_path.get()):
                messagebox.showerror(APP_NAME, "WireGuard is not installed. Please provide the WireGuard MSI.")
                return

            res = _install_wireguard_msi(self.msi_path.get())
            if res.returncode != 0:
                messagebox.showerror(APP_NAME, f"WireGuard install failed:\n{res.stdout}\n{res.stderr}")
                return

        if not _wireguard_installed():
            messagebox.showerror(APP_NAME, "WireGuard install did not complete correctly (wireguard.exe not found).")
            return

        try:
            _copy_config(self.conf_path.get())
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Failed to copy config: {e}")
            return

        res = _install_tunnel_service()
        if res.returncode != 0:
            messagebox.showerror(APP_NAME, f"Tunnel service install failed:\n{res.stdout}\n{res.stderr}")
            return

        _set_service_autostart()

        tray_dst = _copy_tray_app(self.tray_exe_path.get())
        if not _add_run_registry(tray_dst):
            messagebox.showwarning(APP_NAME, "Failed to register tray autostart via HKLM Run. You may need to set it manually.")

        if self.enable_killswitch.get():
            if not self.wg_server_ip.get().strip():
                messagebox.showwarning(APP_NAME, "Kill-switch enabled but WG Server IP is empty. Kill-switch not applied.")
            else:
                _apply_killswitch(True, self.wg_server_ip.get().strip(), self.wg_server_port.get().strip())

        _start_service()
        messagebox.showinfo(APP_NAME, "Installation complete. VPN tunnel service set to start at boot.")


def main():
    root = tk.Tk()
    InstallerUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
