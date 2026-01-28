import tkinter as tk
from tkinter import messagebox
import sys

# Try to import CustomTkinter with a fail-safe
try:
    import customtkinter as ctk
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Missing Libraries", "Critical Error: 'customtkinter' library is missing.\n\nPlease run RUN_APP.bat to install it automatically.")
    sys.exit(1)
import os
import shutil
import subprocess
import datetime
import threading
import time
import ctypes
from ctypes import wintypes
import sys
import webbrowser # For launching links
import base64
import uuid
import urllib.request
import json


try:
    import pyperclip
except ImportError:
    pyperclip = None

try:
    from PIL import Image
except ImportError:
    Image = None

# --- CONFIG & ASSETS ---
try:
    # Fix Taskbar Icon Grouping (Important for Windows)
    myappid = 'system.manager.ultimate.v5' # arbitrary string
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
except: pass

CURRENT_VERSION = "5.0"
GITHUB_REPO_URL = "https://api.github.com/repos/YOUR_GITHUB_USER/YOUR_REPO_NAME/releases/latest"

try:
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("dark-blue")
except: pass

# --- WINDOWS API FOR RAM & MUTEX ---
from ctypes import wintypes
import ctypes
import winreg
try:
    import speedtest # Added for Speed Test
except ImportError:
    speedtest = None

# Define NT API for Handle Enumeration
class SYSTEM_HANDLE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ProcessId", wintypes.ULONG),
        ("ObjectTypeNumber", wintypes.BYTE),
        ("Flags", wintypes.BYTE),
        ("Handle", wintypes.USHORT),
        ("Object", ctypes.c_void_p),
        ("GrantedAccess", wintypes.DWORD),
    ]



class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", wintypes.ULARGE_INTEGER),
        ("ullAvailPhys", wintypes.ULARGE_INTEGER),
        ("ullTotalPageFile", wintypes.ULARGE_INTEGER),
        ("ullAvailPageFile", wintypes.ULARGE_INTEGER),
        ("ullTotalVirtual", wintypes.ULARGE_INTEGER),
        ("ullAvailVirtual", wintypes.ULARGE_INTEGER),
        ("ullAvailExtendedVirtual", wintypes.ULARGE_INTEGER),
    ]

try:
    import psutil
except ImportError:
    psutil = None

from collections import deque

class CPUManager:
    def __init__(self):
        self.power_plans = {
            "Balanced": "381b4222-f694-41f0-9685-ff5bb260df2e",
            "High Perf": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
            "Ultimate": "e9a42b02-d5df-448d-aa00-03f14749eb61"
        }
        self.auto_balance_enabled = False
        self.last_balance_time = 0
    
    def get_cpu_info(self):
        if not psutil: return 0, []
        total = psutil.cpu_percent(interval=None)
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        return total, per_core

    def set_power_plan(self, plan_name):
        if plan_name not in self.power_plans: return False
        guid = self.power_plans[plan_name]
        try:
            subprocess.run(f"powercfg /setactive {guid}", shell=True)
            return True
        except: return False

    def optimize_threads(self):
        # Placeholder for future logic if needed
        return True

    def get_cpu_process_list(self, limit=20):
        if not psutil: return []
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                # cpu_percent needs a previous call or interval. 
                # Since we want instant data, we might rely on the background daemon calling this.
                # Or just return what we have. Note: first call is always 0.0.
                c = p.info['cpu_percent']
                if c is None: c = 0.0
                procs.append({
                    'pid': p.info['pid'],
                    'name': p.info['name'],
                    'cpu': c
                })
            except: pass
        
        procs.sort(key=lambda x: x['cpu'], reverse=True)
        return procs[:limit]

    def set_process_priority(self, pid, level):
        """
        level: "IDLE", "BELOW_NORMAL", "NORMAL", "ABOVE_NORMAL", "HIGH", "REALTIME"
        """
        if not psutil: return False
        try:
            p = psutil.Process(pid)
            mapping = {
                "IDLE": psutil.IDLE_PRIORITY_CLASS,
                "BELOW_NORMAL": psutil.BELOW_NORMAL_PRIORITY_CLASS,
                "NORMAL": psutil.NORMAL_PRIORITY_CLASS,
                "ABOVE_NORMAL": psutil.ABOVE_NORMAL_PRIORITY_CLASS,
                "HIGH": psutil.HIGH_PRIORITY_CLASS,
                "REALTIME": psutil.REALTIME_PRIORITY_CLASS
            }
            if level in mapping:
                p.nice(mapping[level])
                return True
        except: pass
        return False

    def set_cpu_affinity(self, pid, mode="all"):
        """
        mode="all" -> Use all cores (Balance)
        mode="0" -> Use core 0 (Restrict)
        """
        if not psutil: return False
        try:
            p = psutil.Process(pid)
            if mode == "all":
                # Enable all logical CPUs
                all_cpus = list(range(psutil.cpu_count()))
                p.cpu_affinity(all_cpus)
            else:
                # Custom affinity list
                if isinstance(mode, list):
                    p.cpu_affinity(mode)
            return True
        except: pass
        return False

    def run_auto_balance(self):
        # Run every 5 seconds
        if time.time() - self.last_balance_time < 5: return
        
        # Get top heavy apps
        procs = self.get_cpu_process_list(limit=3)
        for p in procs:
            # Force 'all' affinity to unpark/spread load
            self.set_cpu_affinity(p['pid'], "all")
            
        self.last_balance_time = time.time()

class RAMManager:
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.psapi = ctypes.windll.psapi
        self.last_optimize_time = 0
        self.cooldown = 60 # Seconds between auto-optimizations
        self.auto_boost_count = 0
        self.last_freed_mb = 0.0
        self.history = deque(maxlen=60) # Store last 60 seconds of usage %
        
        # EXCLUSION LIST to prevent UI glitches/flashing
        self.excluded_processes = {
            "explorer.exe", "dwm.exe", "csrss.exe", "smss.exe", 
            "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", 
            "svchost.exe", "fontdrvhost.exe", "System", "Registry"
        }

    def get_ram_info(self):
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(stat)
        self.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
        
        total_mb = stat.ullTotalPhys / (1024 * 1024)
        avail_mb = stat.ullAvailPhys / (1024 * 1024)
        used_mb = total_mb - avail_mb
        percent = stat.dwMemoryLoad
        
        # Track history
        self.history.append(percent)
        
        return total_mb, used_mb, avail_mb, percent

    def get_process_list(self, limit=15):
        if not psutil: return []
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                mem = p.info['memory_info'].rss / (1024 * 1024) # MB
                procs.append({
                    'pid': p.info['pid'],
                    'name': p.info['name'],
                    'memory': mem
                })
            except: pass
        
        # Sort by memory usage desc
        procs.sort(key=lambda x: x['memory'], reverse=True)
        return procs[:limit]

    def optimize(self):
        # 1. Capture State Before
        stat_before = MEMORYSTATUSEX()
        stat_before.dwLength = ctypes.sizeof(stat_before)
        self.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat_before))
        avail_before = stat_before.ullAvailPhys

        # 2. Optimize
        count = 0
        # Use fast Windows API method
        arr = (wintypes.DWORD * 4096)()
        needed = wintypes.DWORD()
        self.psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(needed))
        num_processes = needed.value // ctypes.sizeof(wintypes.DWORD)
        
        for i in range(num_processes):
            pid = arr[i]
            # Skip PID 0, 4 (System)
            if pid <= 4: continue
            
            hProcess = self.kernel32.OpenProcess(0x0410, False, pid) # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            if hProcess:
                try:
                    # Check Name
                    name_buf = ctypes.create_unicode_buffer(1024)
                    self.psapi.GetModuleBaseNameW(hProcess, 0, name_buf, 1024)
                    p_name = name_buf.value
                    
                    if p_name and p_name.lower() in self.excluded_processes:
                         # Skip critical system UI processes
                         self.kernel32.CloseHandle(hProcess)
                         continue
                         
                    # Re-open with SET_QUOTA permissions to empty set
                    self.kernel32.CloseHandle(hProcess)
                    hProcess = self.kernel32.OpenProcess(0x001F0FFF, False, pid) 
                    if hProcess:
                        self.psapi.EmptyWorkingSet(hProcess)
                        count += 1
                except: pass
                
                if hProcess: self.kernel32.CloseHandle(hProcess)
        
        # 3. Capture State After
        stat_after = MEMORYSTATUSEX()
        stat_after.dwLength = ctypes.sizeof(stat_after)
        self.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat_after))
        avail_after = stat_after.ullAvailPhys

        # 4. Calculate Difference
        freed_bytes = avail_after - avail_before
        if freed_bytes < 0: freed_bytes = 0
        
        self.last_freed_mb = freed_bytes / (1024 * 1024)
        self.last_optimize_time = time.time()
        
        return count, self.last_freed_mb

# --- NETWORK MANAGER ---
class NetworkManager:
    def __init__(self):
        self.history = deque(maxlen=60)
        
    def get_ping(self, host="8.8.8.8"):
        """Returns ping in ms or -1 if failed."""
        try:
            # -n 1 = 1 packet, -w 1000 = 1000ms timeout
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            output = subprocess.check_output(f"ping -n 1 -w 1000 {host}", startupinfo=startupinfo, shell=False).decode()
            
            # Parse 'time=12ms' or 'time<1ms'
            if "time=" in output:
                start = output.find("time=") + 5
                end = output.find("ms", start)
                ms = int(output[start:end].strip())
                self.history.append(ms)
                return ms
            elif "time<1" in output:
                self.history.append(1)
                return 1
        except: pass
        
        self.history.append(0) # 0 means timeout/error for graph
        return -1

    def flush_dns(self):
        try:
            subprocess.run("ipconfig /flushdns", shell=True)
            return True
        except: return False

    def reset_network(self):
        try:
            # Requires Admin usually
            subprocess.run("netsh winsock reset", shell=True)
            subprocess.run("netsh int ip reset", shell=True)
            return True
        except: return False

    def run_speed_test(self, callback):
        def _test():
            try:
                st = speedtest.Speedtest()
                st.get_best_server()
                
                # Download
                dl = st.download() / 1_000_000 # Mbps
                
                # Upload
                ul = st.upload() / 1_000_000 # Mbps
                
                ping = st.results.ping
                
                callback(dl, ul, ping)
            except Exception as e:
                print(f"Speedtest Error: {e}")
                callback(None, None, None)
                
        threading.Thread(target=_test).start()

class SystemRestoreManager:
    def create_restore_point(self, desc="System Manager Auto-Backup", callback=None):
        def _task():
            try:
                # WMIC requires Admin
                # 100 = APPLICATION_INSTALL, 7 = BEGIN_SYSTEM_CHANGE
                cmd = f'wmic /Namespace:\\\\root\\default Path SystemRestore Call CreateRestorePoint "{desc}", 100, 7'
                
                # Check if admin first (wmic usually fails silently or access denied if not admin)
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    if callback: callback(False, "Require Admin privileges")
                    return

                res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if "ReturnValue = 0" in res.stdout:
                    if callback: callback(True, "Success")
                else:
                    if callback: callback(False, "Failed (Check 'System Restore' settings)")
            except Exception as e:
                if callback: callback(False, str(e))
                
        threading.Thread(target=_task).start()

class HardwareManager:
    def get_cpu_temp(self):
        try:
            # Try WMI MSAcpi
            # Value is Kelvin * 10. e.g. 3010 = 301.0 K = 27.85 C
            # (3010 - 2732) / 10 = 27.8 C
            cmd = "wmic /namespace:\\\\root\\wmi PATH MSAcpi_ThermalZoneTemperature get CurrentTemperature"
            out = subprocess.check_output(cmd, shell=True).decode()
            for line in out.splitlines():
                if line.strip().isdigit():
                    k = int(line.strip())
                    c = (k - 2732) / 10.0
                    return c
        except: 
            return None
        return None

class StartupManager:
    def __init__(self):
        self.key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        
    def get_startup_items(self):
        items = []
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.key_path, 0, winreg.KEY_READ)
            info = winreg.QueryInfoKey(key)
            for i in range(info[1]):
                name, val, _ = winreg.EnumValue(key, i)
                items.append((name, val))
            winreg.CloseKey(key)
        except: pass
        return items

    def delete_item(self, name):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.key_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            return True
        except: return False

class CpuFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        # self.auto_balance is now in controller.cpu_mgr.auto_balance_enabled
        # self.auto_balance is now in controller.cpu_mgr.auto_balance_enabled
        
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        valid_plans = ["High Perf", "Balanced"]
        ctk.CTkLabel(header, text="CPU BOOSTER PRO", font=("Kanit", 24, "bold"), text_color="#3da9fc").pack(side="left")
        
        # Main Layout: 2 Columns
        # Left: Core Graphs
        # Right: Process Optimizer
        
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True)
        content.grid_columnconfigure(0, weight=1)
        content.grid_columnconfigure(1, weight=1)
        
        # --- LEFT: Cores ---
        left_panel = ctk.CTkFrame(content, fg_color="#232323", corner_radius=10)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        ctk.CTkLabel(left_panel, text="LOGICAL PROCESSOR LOAD", font=("Kanit", 14), text_color="gray").pack(pady=10)
        
        self.core_container = ctk.CTkFrame(left_panel, fg_color="transparent")
        self.core_container.pack(fill="both", expand=True, padx=20, pady=10)
        self.core_bars = []
        self.cores_setup = False
        
        # --- RIGHT: Optimizer ---
        right_panel = ctk.CTkFrame(content, fg_color="#232323", corner_radius=10)
        right_panel.grid(row=0, column=1, sticky="nsew")
        
        ctk.CTkLabel(right_panel, text="PROCESS OPTIMIZER", font=("Kanit", 14), text_color="gray").pack(pady=10)
        
        # Process List
        self.proc_scroll = ctk.CTkScrollableFrame(right_panel, fg_color="transparent", height=200)
        self.proc_scroll.pack(fill="both", expand=True, padx=10, pady=5)
        self.proc_widgets = []
        
        # Controls for Selected Process
        ctrl_box = ctk.CTkFrame(right_panel, fg_color="transparent")
        ctrl_box.pack(fill="x", padx=10, pady=10)
        
        self.lbl_selected = ctk.CTkLabel(ctrl_box, text="Select a process...", font=("Kanit", 12), anchor="w")
        self.lbl_selected.pack(fill="x", pady=(0, 5))
        
        btn_grid = ctk.CTkFrame(ctrl_box, fg_color="transparent")
        btn_grid.pack(fill="x")
        
        ctk.CTkButton(btn_grid, text="📉 Reduce (Eco)", width=90, fg_color="#2cb67d", height=30,
                      command=lambda: self.apply_priority("IDLE")).pack(side="left", padx=2)
        ctk.CTkButton(btn_grid, text="⚖️ Balance", width=90, fg_color="#3da9fc", height=30,
                      command=self.apply_balance).pack(side="left", padx=2)
        ctk.CTkButton(btn_grid, text="⚡ Speed Up", width=90, fg_color="#ef4565", height=30,
                      command=lambda: self.apply_priority("HIGH")).pack(side="left", padx=2)

        # Global CPU Controls (Bottom)
        global_ctrl = ctk.CTkFrame(self, fg_color="#232323", corner_radius=10)
        global_ctrl.pack(fill="x", pady=20)
        
        row_b = ctk.CTkFrame(global_ctrl, fg_color="transparent")
        row_b.pack(pady=15)
        
        ctk.CTkButton(row_b, text="🚀 Ultimate Performance", width=180, height=40, 
                      fg_color="#ef4565", hover_color="#d93654", font=("Kanit", 14),
                      command=lambda: self.set_plan("High Perf")).pack(side="left", padx=20)
                      
        ctk.CTkButton(row_b, text="🍃 Balanced Mode", width=180, height=40, 
                      fg_color="#2cb67d", hover_color="#208b5e", font=("Kanit", 14),
                      command=lambda: self.set_plan("Balanced")).pack(side="left", padx=20)
                      
        self.sw_balance = ctk.CTkSwitch(global_ctrl, text="Auto-Balance (Persistent)", font=("Kanit", 12), command=self.toggle_balancer)
        if self.controller.cpu_mgr.auto_balance_enabled:
             self.sw_balance.select()
        self.sw_balance.pack(pady=(0, 15))


    def set_plan(self, name):
        if self.controller.cpu_mgr.set_power_plan(name):
            ToastNotification.show_toast("Power Plan", f"Switched to {name}.", "green")

    def toggle_balancer(self):
        self.controller.cpu_mgr.auto_balance_enabled = bool(self.sw_balance.get())
        if self.controller.cpu_mgr.auto_balance_enabled:
            ToastNotification.show_toast("Auto-Balance ON", "System will force heavy apps to use ALL cores.", "green")

    def select_process(self, pid, name):
        self.selected_pid = pid
        self.lbl_selected.configure(text=f"Selected: {name} ({pid})")

    def apply_priority(self, level):
        if not self.selected_pid: return
        if self.controller.cpu_mgr.set_process_priority(self.selected_pid, level):
             ToastNotification.show_toast("Priority Updated", f"Set to {level}", "green")

    def apply_balance(self):
        if not self.selected_pid: return
        if self.controller.cpu_mgr.set_cpu_affinity(self.selected_pid, "all"):
             ToastNotification.show_toast("Affinity Updated", "Process is now using ALL cores.", "green")

    def update_ui(self, *args):
        # 1. Update Cores
        total, per_core = self.controller.cpu_mgr.get_cpu_info()
        
        if not self.cores_setup and per_core:
            num = len(per_core)
            cols = 4
            for i in range(num):
                c_frame = ctk.CTkFrame(self.core_container, fg_color="#1a1a1a", border_width=0)
                c_frame.grid(row=i//cols, column=i%cols, padx=3, pady=3, sticky="nsew")
                self.core_container.grid_columnconfigure(i%cols, weight=1)
                
                # Bars
                ctk.CTkLabel(c_frame, text=f"CPU {i}", font=("Kanit", 9), text_color="gray").pack(anchor="w", padx=4)
                bar = ctk.CTkProgressBar(c_frame, height=6, progress_color="#3da9fc")
                bar.pack(fill="x", padx=4, pady=4)
                self.core_bars.append(bar)
            self.cores_setup = True
            
        for i, val in enumerate(per_core):
            if i < len(self.core_bars):
                self.core_bars[i].set(val / 100)
                color = "#3da9fc"
                if val > 80: color = "#ef4565"
                elif val > 50: color = "#ffcc00"
                self.core_bars[i].configure(progress_color=color)

        # 2. Update Process List (Throttle: every 3s)
        if int(time.time()) % 3 == 0:
            self.refresh_procs()
            
            self.refresh_procs()
            
        # 3. Auto-Balancer Background Logic MOVED to SystemManagerApp global loop

    def refresh_procs(self):
        # Clear
        for w in self.proc_widgets: w.destroy()
        self.proc_widgets = []
        
        procs = self.controller.cpu_mgr.get_cpu_process_list(limit=10)
        for p in procs:
            row = ctk.CTkButton(self.proc_scroll, text=f"{p['cpu']}% | {p['name']}", 
                                fg_color="transparent", border_width=1, border_color="#333",
                                hover_color="#333", anchor="w", font=("Consolas", 11),
                                command=lambda pid=p['pid'], n=p['name']: self.select_process(pid, n))
            row.pack(fill="x", pady=1)
            self.proc_widgets.append(row)

# --- LOGGING & DATA MANAGER ---
import logging
import json

class LogManager:
    def __init__(self):
        self.app_dir = os.path.dirname(os.path.abspath(__file__))
        self.secure_dir = os.path.join(self.app_dir, "secure_data")
        self.log_dir = os.path.join(self.secure_dir, "logs")
        self.data_dir = os.path.join(self.secure_dir, "data")
        self.usage_file = os.path.join(self.data_dir, "usage_history.json")
        
        self.cleanup_old_folders()
        self.setup_directories()
        self.setup_logging()

    def cleanup_old_folders(self):
        """Remove unused folders for security/hygiene."""
        for old in ["rm", "data", "logs"]:
             path = os.path.join(self.app_dir, old)
             if os.path.exists(path):
                 try:
                     shutil.rmtree(path)
                 except: pass

    def setup_directories(self):
        """Ensure critical folders exist."""
        for d in [self.secure_dir, self.log_dir, self.data_dir]:
            if not os.path.exists(d):
                os.makedirs(d)

    def setup_logging(self):
        """Configure system logging."""
        log_file = os.path.join(self.log_dir, "system_events.log")
        
        # Create a logger
        self.logger = logging.getLogger("SystemManager")
        self.logger.setLevel(logging.INFO)
        
        # File Handler (Rotational logic could be added here)
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        
        # Clean existing handlers to prevent duplicates
        if self.logger.hasHandlers():
            self.logger.handlers.clear()
            
        self.logger.addHandler(fh)
        self.log_event("System", "Application Started - Logging Initialized")

    def log_event(self, category, message):
        """Log a specific event."""
        self.logger.info(f"[{category}] {message}")
        self.save_usage_stat(category)


    def save_usage_stat(self, category):
        """Update rudimentary usage stats in JSON."""
        stats = {}
        try:
            if os.path.exists(self.usage_file):
                with open(self.usage_file, 'r') as f:
                    stats = json.load(f)
        except: pass
        
        if category not in stats: stats[category] = 0
        stats[category] += 1
        
        try:
            with open(self.usage_file, 'w') as f:
                json.dump(stats, f, indent=4)
        except: pass

# --- GAME ACCOUNT MANAGER (BACKEND) ---


# --- TOAST NOTIFICATION ---
class ToastNotification(ctk.CTkToplevel):
    def __init__(self, title, message, color="green"):
        super().__init__()
        self.geometry("350x100")
        self.overrideredirect(True) # Remove window borders
        self.attributes("-topmost", True)
        
        # Position at bottom right
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = screen_w - 370
        y = screen_h - 150
        self.geometry(f"+{x}+{y}")
        
        # UI
        self.configure(fg_color="#1a1a1a")
        
        # Colored Strip
        strip_color = "#2cb67d" if color == "green" else "#ef4565"
        self.strip = ctk.CTkFrame(self, width=10, fg_color=strip_color, corner_radius=0)
        self.strip.pack(side="left", fill="y")
        
        # Content
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        self.lbl_title = ctk.CTkLabel(self.content, text=title, font=("Roboto", 16, "bold"), text_color="white", anchor="w")
        self.lbl_title.pack(fill="x")
        
        self.lbl_msg = ctk.CTkLabel(self.content, text=message, font=("Roboto", 12), text_color="#ccc", anchor="w")
        self.lbl_msg.pack(fill="x")
        
        # Close Timer
        self.after(4000, self.destroy)

    @staticmethod
    def show_toast(title, message, color="green"):
        try:
            t = ToastNotification(title, message, color)
        except: pass

# --- UPDATE MANAGER ---
class UpdateManager:
    def __init__(self, controller):
        self.controller = controller
        self.download_url = None
        self.new_version = None
        
    def check_for_updates(self, callback=None):
        def _check():
            try:
                # 1. Fetch latest release info from GitHub API
                with urllib.request.urlopen(GITHUB_REPO_URL) as response:
                    data = json.loads(response.read().decode())
                    
                latest_tag = data.get('tag_name', '').strip()
                # Remove 'v' if present e.g. v1.0 -> 1.0
                if latest_tag.lower().startswith('v'):
                    latest_tag = latest_tag[1:]
                    
                self.new_version = latest_tag
                
                # Compare versions (simple string compare for now, or float)
                # Ideally use semver, but let's assume direct inequality
                if latest_tag != CURRENT_VERSION:
                    # Found update
                    assets = data.get('assets', [])
                    zip_url = None
                    for asset in assets:
                        if asset['name'].endswith('.zip'):
                            zip_url = asset['browser_download_url']
                            break
                    
                    if zip_url:
                        self.download_url = zip_url
                        if callback: callback(True, latest_tag)
                        return
                
                if callback: callback(False, "You are up to date!")
                    
            except Exception as e:
                print(f"Update Check Error: {e}")
                if callback: callback(False, f"Check failed: {e}")
                
        threading.Thread(target=_check).start()

    def start_update(self):
        if not self.download_url: return
        
        # We need to launch updater.py
        # It needs: url, install_dir, pid, zip_name
        
        install_dir = os.path.dirname(os.path.abspath(__file__))
        pid = os.getpid()
        zip_name = "update.zip"
        
        # Check if updater.py exists
        updater_script = os.path.join(install_dir, "updater.py")
        if not os.path.exists(updater_script):
            messagebox.showerror("Error", "updater.py not found!")
            return
            
        cmd = [sys.executable, updater_script, self.download_url, install_dir, str(pid), zip_name]
        
        # Launch independent process
        subprocess.Popen(cmd, creationflags=subprocess.CREATIONFLAGS_DETACHED_PROCESS if sys.platform=='win32' else 0)
        
        # Close App
        self.controller.destroy()
        sys.exit(0)

# --- APP ---
class SystemManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Setup Window
        self.title("System Manager V5.0 Ultimate")
        self.geometry("1000x700")
        self.minsize(900, 650)
        
        # Data
        self.logger = LogManager()
        self.ram_mgr = RAMManager()
        self.cpu_mgr = CPUManager()
        self.net_mgr = NetworkManager()
        self.startup_mgr = StartupManager()
        self.restore_mgr = SystemRestoreManager()
        self.hw_mgr = HardwareManager()
        self.update_mgr = UpdateManager(self)
        self.auto_ram_enabled = False
        self.auto_ram_threshold = 80
        self.game_mode_active = False # New Flag
        self.current_frame = None

        # Icon Setup (Robust)
        self.auto_ram_threshold = 80
        self.current_frame = None

        # Icon Setup (Robust)
        try:
            icon_path = None
            if os.path.exists("app_icon.ico"):
                self.iconbitmap("app_icon.ico")
                icon_path = "app_icon.ico"
            elif os.path.exists("app_icon.png"):
                # Fallback for PNG (Tkinter PhotoImage)
                icon_img = tk.PhotoImage(file="app_icon.png")
                self.iconphoto(True, icon_img)
                icon_path = "app_icon.png"
        except Exception as e:
            print(f"Icon Error: {e}")


        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. Sidebar
        self.setup_sidebar()

        # 2. Main Content Area
        self.main_content = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        # Start
        self.show_home()
        self.after(1000, self.global_loop)

    def setup_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#1a1a1a")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1) # Spacer at bottom
        
        # Title & Logo
        title_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        title_frame.pack(fill="x", pady=(30, 20), padx=20)
        
        # Logo Image
        try:
            if Image and os.path.exists("app_icon.png"):
                pil_img = Image.open("app_icon.png")
                logo_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(80, 80))
                ctk.CTkLabel(title_frame, text="", image=logo_img).pack(pady=(0, 10))
        except: pass
        
        ctk.CTkLabel(title_frame, text="SYSTEM", font=("Kanit", 22, "bold"), text_color="white", anchor="w").pack(fill="x")
        ctk.CTkLabel(title_frame, text="MANAGER 5.0", font=("Kanit", 16), text_color="#3da9fc", anchor="w").pack(fill="x")
        
        # Navigation Container for gap-free stacking
        nav_container = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        nav_container.pack(fill="x", pady=10)
        
        # Nav Buttons (Thai)
        self.btn_home = self.create_nav_btn(nav_container, "🏠  หน้าหลัก", self.show_home)
        self.btn_ram = self.create_nav_btn(nav_container, "🚀  เร่งความเร็ว", self.show_ram)
        self.btn_cpu = self.create_nav_btn(nav_container, "⚡  เร่ง CPU", self.show_cpu)
        self.btn_net = self.create_nav_btn(nav_container, "🌐  เน็ตบูสเตอร์", self.show_network)
        self.btn_game = self.create_nav_btn(nav_container, "🎮  โหมดเกม", self.show_game)
        self.btn_start = self.create_nav_btn(nav_container, "📂  จัดการเริ่มระบบ", self.show_startup)
        self.btn_clean = self.create_nav_btn(nav_container, "🧹  ล้างขยะ", self.show_cleaner)
        self.btn_shut = self.create_nav_btn(nav_container, "⏱️  ตั้งเวลาปิด", self.show_shutdown)
        
        # Spacer
        ctk.CTkFrame(self.sidebar, fg_color="transparent", height=20).pack()
        
        # Update Button
        self.btn_update = self.create_nav_btn(self.sidebar, "🔄  Check Updates", self.do_update_check)
        self.btn_update.pack(fill="x", pady=10)
        
    def do_update_check(self):
        self.btn_update.configure(state="disabled", text="Checking...")
        
        def on_result(found, msg):
            self.btn_update.configure(state="normal", text="🔄  Check Updates")
            if found:
                # Ask user
                ans = messagebox.askyesno("Update Available", f"New version {msg} is available!\n\nDo you want to update now?\n(The app will close and restart)")
                if ans:
                    self.update_mgr.start_update()
            else:
                ToastNotification.show_toast("Update", msg, "blue")
                
        self.update_mgr.check_for_updates(on_result)

    def create_nav_btn(self, parent, text, cmd):
        btn = ctk.CTkButton(parent, text=text, command=cmd, 
                            fg_color="transparent", 
                            text_color="gray90", 
                            hover_color="#333333", 
                            anchor="w", 
                            height=45,
                            font=("Kanit", 14),
                            corner_radius=8)
        btn.pack(fill="x", padx=10, pady=4)
        return btn

    def switch_frame(self, frame_class, **kwargs):
        if self.current_frame is not None:
            self.current_frame.destroy()
        self.current_frame = frame_class(self.main_content, self, **kwargs)
        self.current_frame.pack(fill="both", expand=True)

    def show_home(self): self.switch_frame(HomeFrame)
    # def show_games(self): self.switch_frame(GameFrame)
    def show_ram(self): self.switch_frame(RamFrame)
    def show_cpu(self): self.switch_frame(CpuFrame)
    def show_network(self): self.switch_frame(NetworkFrame)
    def show_startup(self): self.switch_frame(StartupFrame)
    def show_game(self): self.switch_frame(GameModeFrame)
    def show_cleaner(self): self.switch_frame(CleanerFrame)
    def show_shutdown(self): self.switch_frame(ShutdownFrame)

    # --- GLOBAL LOOP ---
    def global_loop(self):
        # Update RAM Data globally
        tot, usd, avl, per = self.ram_mgr.get_ram_info()
        
        # Auto-Boost Logic
        if self.auto_ram_enabled and per > self.auto_ram_threshold:
            if time.time() - self.ram_mgr.last_optimize_time > self.ram_mgr.cooldown:
                
                def _auto_run():
                    c, freed = self.ram_mgr.optimize()
                    self.ram_mgr.auto_boost_count += 1
                    # Show toast on main thread
                    self.after(0, lambda: ToastNotification.show_toast(
                        "Auto-Boost Triggered!", 
                        f"Usage hit {per}% (> {self.auto_ram_threshold}%). Freed {freed:.1f} MB."
                    ))
                
                threading.Thread(target=_auto_run).start()

        # Auto-Balance Logic (Persistent)
        if self.cpu_mgr.auto_balance_enabled:
             threading.Thread(target=self.cpu_mgr.run_auto_balance).start()

        # Game Mode Logic (Foreground Boost)
        if self.game_mode_active:
             def _boost_fg():
                 try:
                     pid = self.cpu_mgr.get_foreground_pid()
                     if pid:
                         self.cpu_mgr.set_priority(pid, "High")
                         # Also exclude from RAM cleanup logic dynamically
                         try:
                             p = psutil.Process(pid)
                             self.ram_mgr.excluded_processes.add(p.name())
                         except: pass
                 except: pass
             threading.Thread(target=_boost_fg).start()

        # Shutdown Check
        if hasattr(self, 'shutdown_target') and self.shutdown_target:
             rem = self.shutdown_target - datetime.datetime.now()
             if rem.total_seconds() <= 0:
                 self.shutdown_target = None
                 subprocess.run("shutdown /a", shell=True) # Safety
             
        # Propagate to current frame if it has an update method
        if self.current_frame and hasattr(self.current_frame, 'update_ui'):
            self.current_frame.update_ui(tot, usd, avl, per)
            
        self.after(1000, self.global_loop)


# --- PAGES ---

# --- FARM MANAGER (WATCHDOG) ---


# --- PAGES ---

class HomeFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        
        ctk.CTkLabel(self, text="DASHBOARD", font=("Roboto", 24, "bold")).pack(anchor="w", pady=(0, 20))
        
        # Status Grid
        self.grid_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.grid_frame.pack(fill="x")
        
        self.card_ram = self.create_stat_card(self.grid_frame, "RAM Usage", "0%", "#3da9fc", 0)
        self.card_cpu = self.create_stat_card(self.grid_frame, "CPU Temp", "N/A", "#ef4565", 1)
        
        ctk.CTkLabel(self, text="Quick Actions", font=("Roboto", 18, "bold")).pack(anchor="w", pady=(40, 10))
        
        act_frame = ctk.CTkFrame(self, fg_color="transparent")
        act_frame.pack(fill="x")
        
        ctk.CTkButton(act_frame, text="Boost RAM Now", command=controller.show_ram, height=40, fg_color="#ef4565", hover_color="#d93654").pack(side="left", padx=(0,10))
        ctk.CTkButton(act_frame, text="Clean Junk", command=controller.show_cleaner, height=40, fg_color="#ffcc00", text_color="black", hover_color="#e6b800").pack(side="left", padx=(0,10))
        ctk.CTkButton(act_frame, text="Create Restore Point", command=self.do_backup, height=40, fg_color="#2cb67d", hover_color="#208b5e").pack(side="left")

    def do_backup(self):
        ToastNotification.show_toast("System Backup", "Creating Restore Point...\nThis may take a moment.", "blue")
        def on_done(success, msg):
            color = "green" if success else "red"
            title = "Backup Complete" if success else "Backup Failed"
            self.after(0, lambda: ToastNotification.show_toast(title, msg, color))
            
        self.controller.restore_mgr.create_restore_point(callback=on_done)

    def create_stat_card(self, parent, title, value, color, col):
        card = ctk.CTkFrame(parent, fg_color="#2b2b2b", corner_radius=10)
        # Configure parent to expand this column
        parent.grid_columnconfigure(col, weight=1)
        card.grid(row=0, column=col, padx=10, sticky="ew")
        
        ctk.CTkLabel(card, text=title, font=("Roboto", 14), text_color="gray").pack(padx=20, pady=(20, 5), anchor="w")
        lbl = ctk.CTkLabel(card, text=value, font=("Roboto", 32, "bold"), text_color=color)
        lbl.pack(padx=20, pady=(0, 20), anchor="w")
        return lbl

    def update_ui(self, tot, usd, avl, per):
        self.card_ram.configure(text=f"{per}%")
        
        # Update CPU Temp
        if int(time.time()) % 2 == 0: # Every 2 sec
            temp = self.controller.hw_mgr.get_cpu_temp()
            if temp:
                self.card_cpu.configure(text=f"{temp:.1f} °C")
                if temp > 80: self.card_cpu.configure(text_color="#ef4565")
                elif temp > 60: self.card_cpu.configure(text_color="#ffcc00")
                else: self.card_cpu.configure(text_color="#2cb67d")
            else:
                self.card_cpu.configure(text="N/A", text_color="gray")

class RamFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(header, text="RAM OPTIMIZER PRO", font=("Kanit", 24, "bold"), text_color="#ffcc00").pack(side="left")
        ctk.CTkButton(header, text="Apply Optimize", width=120, height=32, fg_color="#ffcc00", text_color="black", hover_color="#e6b800", font=("Kanit", 13, "bold"), command=self.manual_opt).pack(side="right")

        # 1. Top Dashboard (3 Cards)
        dash_grid = ctk.CTkFrame(self, fg_color="transparent")
        dash_grid.pack(fill="x", pady=(0, 20))
        dash_grid.grid_columnconfigure((0,1,2), weight=1)
        
        self.card_usage = self.create_status_card(dash_grid, 0, "Usage", "0%", "#ef4565")
        self.card_free = self.create_status_card(dash_grid, 1, "Available", "0 GB", "#2cb67d")
        self.card_total = self.create_status_card(dash_grid, 2, "Total RAM", "0 GB", "#3da9fc")

        # 2. Middle Section (Graph + Process List)
        mid_frame = ctk.CTkFrame(self, fg_color="transparent")
        mid_frame.pack(fill="both", expand=True)
        mid_frame.grid_columnconfigure(0, weight=2)
        mid_frame.grid_columnconfigure(1, weight=1)

        # -- Left: Usage Graph --
        graph_container = ctk.CTkFrame(mid_frame, fg_color="#232323", corner_radius=10)
        graph_container.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        ctk.CTkLabel(graph_container, text="Live Usage History (60s)", font=("Kanit", 14), text_color="gray").pack(anchor="w", padx=15, pady=(15, 5))
        
        self.canvas_h = 180
        self.canvas = ctk.CTkCanvas(graph_container, height=self.canvas_h, bg="#1a1a1a", highlightthickness=0)
        self.canvas.pack(fill="x", padx=15, pady=(0, 15), expand=True)

        # -- Right: Top Processes --
        proc_container = ctk.CTkFrame(mid_frame, fg_color="#232323", corner_radius=10)
        proc_container.grid(row=0, column=1, sticky="nsew")
        
        ctk.CTkLabel(proc_container, text="Top Memory Users", font=("Kanit", 14), text_color="gray").pack(anchor="w", padx=15, pady=(15, 5))
        
        # Scrollable list
        self.proc_scroll = ctk.CTkScrollableFrame(proc_container, fg_color="transparent", height=180)
        self.proc_scroll.pack(fill="both", expand=True, padx=5, pady=5)
        self.proc_widgets = [] # Keep track to destroy old

        # 3. Bottom Controls
        ctrl_frame = ctk.CTkFrame(self, fg_color="#232323", corner_radius=10)
        ctrl_frame.pack(fill="x", pady=20)
        
        # Slider & Switch
        row1 = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        row1.pack(fill="x", padx=20, pady=20)
        
        self.switch_auto = ctk.CTkSwitch(row1, text="Auto-Boost", font=("Kanit", 14), command=self.toggle_auto, progress_color="#ffcc00")
        if self.controller.auto_ram_enabled: self.switch_auto.select()
        self.switch_auto.pack(side="left")
        
        self.lbl_thresh = ctk.CTkLabel(row1, text=f"Trigger: {self.controller.auto_ram_threshold}%", font=("Kanit", 14), width=100)
        self.lbl_thresh.pack(side="right")
        
        self.slider = ctk.CTkSlider(row1, from_=50, to=95, number_of_steps=45, command=self.on_slide, button_color="#ffcc00", button_hover_color="#e6b800")
        self.slider.set(self.controller.auto_ram_threshold)
        self.slider.pack(side="right", fill="x", expand=True, padx=20)

    def create_status_card(self, parent, col, title, initial_val, color):
        card = ctk.CTkFrame(parent, fg_color="#232323", corner_radius=12, height=100)
        card.grid(row=0, column=col, sticky="ew", padx=5)
        
        ctk.CTkLabel(card, text=title, font=("Kanit", 14), text_color="gray").pack(anchor="w", padx=15, pady=(15, 0))
        val_lbl = ctk.CTkLabel(card, text=initial_val, font=("Kanit", 28, "bold"), text_color=color)
        val_lbl.pack(anchor="w", padx=15, pady=(5, 15))
        return val_lbl

    def update_ui(self, tot, usd, avl, per):
        # Update Cards
        used_gb = usd / 1024
        total_gb = tot / 1024
        
        self.card_usage.configure(text=f"{int(per)}%")
        self.card_free.configure(text=f"{avl/1024:.1f} GB")
        self.card_total.configure(text=f"{total_gb:.1f} GB")
        
        # Color shift for usage
        if per > 85: self.card_usage.configure(text_color="#ef4565") # Red
        elif per > 60: self.card_usage.configure(text_color="#ffcc00") # Yellow
        else: self.card_usage.configure(text_color="#2cb67d") # Green

        # Draw Graph
        self.draw_graph()
        
        # Update Process List (only every 2 seconds to avoid lag)
        if int(time.time()) % 2 == 0:
            self.refresh_process_list()

    def draw_graph(self):
        self.canvas.delete("all")
        history = list(self.controller.ram_mgr.history)
        if not history: return
        
        w = self.canvas.winfo_width()
        h = self.canvas_h
        count = len(history)
        step_x = w / (60 - 1) if count > 0 else 0
        
        # Draw grid lines
        for i in range(1, 5):
            y = i * (h/5)
            self.canvas.create_line(0, y, w, y, fill="#2a2a2a", width=1)

        # Points
        points = []
        for i, val in enumerate(history):
            if count < 60:
                # Align to right if filling up
                x = w - ((count - 1 - i) * step_x) 
            else:
                x = i * step_x
            
            # Y axis (0-100%) inverted
            y = h - (val / 100 * h)
            points.append(x)
            points.append(y)
            
        if len(points) >= 4:
            self.canvas.create_line(points, fill="#3da9fc", width=2, smooth=True)
            
            # Fill Polygon (Gradient fake)
            points += [points[-2], h, points[0], h]
            # Tkinter doesn't support alpha, so stipple is alternative but ugly.
            # Using simple line is cleaner for modern look.

    def refresh_process_list(self):
        # Clear old
        for w in self.proc_widgets: w.destroy()
        self.proc_widgets = []
        
        top_procs = self.controller.ram_mgr.get_process_list(limit=8)
        
        for p in top_procs:
            row = ctk.CTkFrame(self.proc_scroll, fg_color="transparent")
            row.pack(fill="x", pady=2)
            
            ctk.CTkLabel(row, text=p['name'], font=("Kanit", 12), width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=f"{p['memory']:.0f} MB", font=("Kanit", 12, "bold"), text_color="#ef4565").pack(side="right")
            
            self.proc_widgets.append(row)

    def toggle_auto(self):
        self.controller.auto_ram_enabled = bool(self.switch_auto.get())

    def on_slide(self, val):
        self.controller.auto_ram_threshold = int(val)
        self.lbl_thresh.configure(text=f"Trigger: {int(val)}%")

    def manual_opt(self):
        c, freed = self.controller.ram_mgr.optimize()
        ToastNotification.show_toast("Optimizer", f"Freed {freed:.1f} MB from {c} apps.", "green")


class CleanerFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        
        ctk.CTkLabel(self, text="JUNK CLEANER", font=("Roboto", 24, "bold"), text_color="#ef4565").pack(anchor="w", pady=(0, 20))
        
        opt_frame = ctk.CTkFrame(self)
        opt_frame.pack(fill="x")
        
        self.chk_sys = ctk.CTkCheckBox(opt_frame, text="System Temp (C:\\Windows\\Temp)", onvalue=True, offvalue=False)
        self.chk_sys.select()
        self.chk_sys.pack(anchor="w", padx=20, pady=10)
        
        self.chk_usr = ctk.CTkCheckBox(opt_frame, text="User Temp (%TEMP%)", onvalue=True, offvalue=False)
        self.chk_usr.select()
        self.chk_usr.pack(anchor="w", padx=20, pady=5)

        self.chk_pre = ctk.CTkCheckBox(opt_frame, text="Prefetch (System Cache)", onvalue=True, offvalue=False)
        self.chk_pre.select()
        self.chk_pre.pack(anchor="w", padx=20, pady=5)
        
        self.chk_bin = ctk.CTkCheckBox(opt_frame, text="Empty Recycle Bin", onvalue=True, offvalue=False)
        self.chk_bin.select()
        self.chk_bin.pack(anchor="w", padx=20, pady=5)
        
        self.chk_browser = ctk.CTkCheckBox(opt_frame, text="Browser Cache (Chrome/Edge)", onvalue=True, offvalue=False)
        self.chk_browser.pack(anchor="w", padx=20, pady=(0, 20))
        
        self.log_txt = ctk.CTkTextbox(self, height=300)
        self.log_txt.pack(fill="x", pady=20)
        
        ctk.CTkButton(self, text="DEEP CLEAN NOW", height=50, fg_color="#ef4565", hover_color="#d93654", font=("Roboto", 16, "bold"), command=self.run_clean).pack(fill="x")

    def run_clean(self):
        self.log_txt.delete("0.0", "end")
        self.log_txt.insert("0.0", "Starting cleanup...\n")
        
        sys_temp = self.chk_sys.get()
        usr_temp = self.chk_usr.get()
        prefetch = self.chk_pre.get()
        recycle = self.chk_bin.get()
        browsers = self.chk_browser.get()
        
        def _clean_thread():
             targets = []
             if sys_temp: targets.append(os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Temp'))
             if usr_temp: targets.append(os.environ.get('TEMP'))
             if prefetch: targets.append(os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Prefetch'))
             
             if browsers:
                 local = os.environ.get('LOCALAPPDATA')
                 if local:
                     targets.append(os.path.join(local, 'Google\\Chrome\\User Data\\Default\\Cache\\Cache_Data'))
                     targets.append(os.path.join(local, 'Microsoft\\Edge\\User Data\\Default\\Cache\\Cache_Data'))
                     targets.append(os.path.join(local, 'BraveSoftware\\Brave-Browser\\User Data\\Default\\Cache\\Cache_Data'))
             
             total_size = 0
             
             # 1. File Cleanup
             for root_dir in targets:
                 self.log_txt.insert("end", f"Scanning {root_dir}...\n")
                 if not os.path.exists(root_dir): continue
                 
                 for r, d, f in os.walk(root_dir):
                     for file in f:
                         try:
                             p = os.path.join(r, file)
                             s = os.path.getsize(p)
                             os.remove(p)
                             total_size += s
                         except: pass
                         
             # 2. Recycle Bin
             if recycle:
                 self.log_txt.insert("end", "Emptying Recycle Bin...\n")
                 try:
                     # SHEmptyRecycleBinW(hwnd, root_path, flags)
                     # Flags: 1=NoSound, 2=NoConfirm, 4=NoProgress
                     ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 7)
                     self.log_txt.insert("end", "Recycle Bin Cleared.\n")
                 except Exception as e:
                     self.log_txt.insert("end", f"Recycle Bin Error: {e}\n")
             
             mb = total_size / (1024*1024)
             self.controller.logger.log_event("Junk Cleaner", f"Cleanup Finished. Freed {mb:.2f} MB")
             self.log_txt.insert("end", f"\nDONE! Freed {mb:.2f} MB (files) + Recycle Bin.\n")
             # Fix Thread Safety: Schedule UI update on main thread
             self.after(0, lambda: ToastNotification.show_toast("Cleanup Finished", f"Recovered {mb:.2f} MB.", "green"))

        threading.Thread(target=_clean_thread).start()

class ShutdownFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        
        ctk.CTkLabel(self, text="SHUTDOWN TIMER", font=("Roboto", 24, "bold"), text_color="#3da9fc").pack(anchor="w", pady=(0, 20))
        
        # Clock
        self.lbl_clock = ctk.CTkLabel(self, text="00:00:00", font=("Consolas", 60, "bold"))
        self.lbl_clock.pack(pady=20)
        
        # Input
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(pady=20)
        
        ctk.CTkLabel(self.input_frame, text="Set Hour").grid(row=0, column=0, padx=10)
        ctk.CTkLabel(self.input_frame, text="Set Minute").grid(row=0, column=1, padx=10)
        
        self.entry_h = ctk.CTkEntry(self.input_frame, width=60, justify="center", font=("Consolas", 20))
        self.entry_h.grid(row=1, column=0, padx=10, pady=10)
        self.entry_h.insert(0, datetime.datetime.now().strftime("%H"))
        
        self.entry_m = ctk.CTkEntry(self.input_frame, width=60, justify="center", font=("Consolas", 20))
        self.entry_m.grid(row=1, column=1, padx=10, pady=10)
        self.entry_m.insert(0, datetime.datetime.now().strftime("%M"))
        
        self.btn_action = ctk.CTkButton(self, text="START TIMER", height=50, fg_color="#3da9fc", font=("Roboto", 16, "bold"), command=self.toggle_timer)
        self.btn_action.pack(fill="x", pady=20)
        
        self.lbl_status = ctk.CTkLabel(self, text="", text_color="gray")
        self.lbl_status.pack()

    def update_ui(self, *args):
        # Clock
        self.lbl_clock.configure(text=datetime.datetime.now().strftime("%H:%M:%S"))
        
        # Status
        if hasattr(self.controller, 'shutdown_target') and self.controller.shutdown_target:
             rem = self.controller.shutdown_target - datetime.datetime.now()
             s = int(rem.total_seconds())
             self.lbl_status.configure(text=f"Shutting down in: {datetime.timedelta(seconds=s)}", text_color="#ef4565")
             self.btn_action.configure(text="CANCEL TIMER", fg_color="#ef4565", hover_color="#d93654")
        else:
             self.lbl_status.configure(text="Timer inactive", text_color="gray")
             self.btn_action.configure(text="START TIMER", fg_color="#3da9fc", hover_color="#1e90ff")

    def toggle_timer(self):
        if hasattr(self.controller, 'shutdown_target') and self.controller.shutdown_target:
            self.controller.shutdown_target = None
            subprocess.run("shutdown /a", shell=True)
            ToastNotification.show_toast("Timer Cancelled", "Scheduled shutdown has been cancelled.", "red")
        else:
            try:
                h = int(self.entry_h.get())
                m = int(self.entry_m.get())
                now = datetime.datetime.now()
                target = now.replace(hour=h, minute=m, second=0)
                if target <= now: target += datetime.timedelta(days=1)
                
                sec = int((target - now).total_seconds())
                subprocess.run(f"shutdown /s /t {sec}", shell=True)
                
                self.controller.shutdown_target = target
                self.controller.logger.log_event("Shutdown Timer", f"Scheduled shutdown at {target.strftime('%H:%M')}")
                ToastNotification.show_toast("Timer Started", f"Shutdown scheduled for {target.strftime('%H:%M')}", "green")
            except:
                messagebox.showerror("Error", "Invalid time format")

class NetworkFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        
        ctk.CTkLabel(self, text="NETWORK & INTERNET BOOSTER", font=("Roboto", 24, "bold"), text_color="#3da9fc").pack(anchor="w", pady=(0, 20))
        
        # --- Top: Actions ---
        act_frame = ctk.CTkFrame(self, fg_color="transparent")
        act_frame.pack(fill="x", pady=10)
        
        ctk.CTkButton(act_frame, text="Flush DNS Cache", width=200, height=40, fg_color="#2cb67d", 
                      font=("Roboto", 14), command=self.do_flush).pack(side="left", padx=(0, 20))
                      
        ctk.CTkButton(act_frame, text="Reset Network Stack", width=200, height=40, fg_color="#ef4565", 
                      font=("Roboto", 14), command=self.do_reset).pack(side="left")
        
        # --- Ping Graph ---
        graph_box = ctk.CTkFrame(self, fg_color="#232323", corner_radius=10)
        graph_box.pack(fill="both", expand=True, pady=20)
        
        header = ctk.CTkFrame(graph_box, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=15)
        ctk.CTkLabel(header, text="Real-time Ping (Google DNS)", font=("Kanit", 14), text_color="gray").pack(side="left")
        self.lbl_ping = ctk.CTkLabel(header, text="0 ms", font=("Kanit", 20, "bold"), text_color="#3da9fc")
        self.lbl_ping.pack(side="right")
        
        self.canvas_h = 200
        self.canvas = ctk.CTkCanvas(graph_box, height=self.canvas_h, bg="#1a1a1a", highlightthickness=0)
        self.canvas.pack(fill="x", padx=15, pady=(0, 15), expand=True)

        # --- Speed Test Section ---
        speed_box = ctk.CTkFrame(self, fg_color="#2b2b2b", corner_radius=10)
        speed_box.pack(fill="x", pady=20)
        
        self.btn_test = ctk.CTkButton(speed_box, text="RUN SPEED TEST (Mbps)", height=50, 
                                      fg_color="#3da9fc", font=("Kanit", 16, "bold"), 
                                      command=self.start_speed_test)
        self.btn_test.pack(side="left", padx=20, pady=20)
        
        # Results
        res_frame = ctk.CTkFrame(speed_box, fg_color="transparent")
        res_frame.pack(side="left", fill="x", expand=True, padx=20)
        
        self.lbl_dl = ctk.CTkLabel(res_frame, text="Download: -- Mbps", font=("Kanit", 16), text_color="#2cb67d", anchor="w")
        self.lbl_dl.pack(fill="x")
        
        self.lbl_ul = ctk.CTkLabel(res_frame, text="Upload: -- Mbps", font=("Kanit", 16), text_color="#ef4565", anchor="w")
        self.lbl_ul.pack(fill="x")

    def start_speed_test(self):
        self.btn_test.configure(state="disabled", text="TESTING... (PLEASE WAIT)")
        self.lbl_dl.configure(text="Download: Testing...")
        self.lbl_ul.configure(text="Upload: Testing...")
        
        def on_complete(dl, ul, ping):
            # Back on main thread check
            self.after(0, lambda: self._show_results(dl, ul, ping))
            
        self.controller.net_mgr.run_speed_test(on_complete)
        
    def _show_results(self, dl, ul, ping):
        self.btn_test.configure(state="normal", text="RUN SPEED TEST (Mbps)")
        if dl is not None:
             self.lbl_dl.configure(text=f"Download: {dl:.2f} Mbps")
             self.lbl_ul.configure(text=f"Upload: {ul:.2f} Mbps")
             ToastNotification.show_toast("Speed Test Complete", f"DL: {dl:.0f} Mbps | UL: {ul:.0f} Mbps", "green")
        else:
             self.lbl_dl.configure(text="Download: Error")
             self.lbl_ul.configure(text="Upload: Error")
             ToastNotification.show_toast("Error", "Speed Test Failed (Check Connection)", "red")

    def do_flush(self):
        if self.controller.net_mgr.flush_dns():
            ToastNotification.show_toast("Network", "DNS Cache Flushed Successfully.", "green")
        else:
            ToastNotification.show_toast("Error", "Failed to flush DNS.", "red")
            
    def do_reset(self):
        if self.controller.net_mgr.reset_network():
            ToastNotification.show_toast("Network Reset", "Network reset complete.\nPlease restart your PC.", "blue")
        else:
            ToastNotification.show_toast("Error", "Failed to reset network (Need Admin).", "red")

    def update_ui(self, *args):
        # 1. Get Ping
        # Running ping in main thread might lag UI slightly (1 sec timeout).
        # We can optimize this by running it in thread, but for simplicity here we assume low timeout.
        # Ideally, we used `threading` but let's see. 
        # Actually proper way: Thread updates the history, UI just reads it.
        pass # UI updates handled by background thread via controller? 
        # For now, let's keep it simple: Controller Global Loop calls `net_mgr` in a thread?
        
        # Better: run ping in background thread in loop
        threading.Thread(target=self._update_ping).start()
        
    def _update_ping(self):
        ms = self.controller.net_mgr.get_ping()
        self.after(0, lambda: self.draw_graph(ms))

    def draw_graph(self, current_ms):
        self.lbl_ping.configure(text=f"{current_ms} ms" if current_ms >=0 else "Timeout")
        color = "#2cb67d"
        if current_ms > 100: color = "#ffcc00"
        if current_ms > 200 or current_ms == -1: color = "#ef4565"
        self.lbl_ping.configure(text_color=color)
        
        self.canvas.delete("all")
        history = list(self.controller.net_mgr.history)
        if not history: return
        
        w = self.canvas.winfo_width()
        h = self.canvas_h
        count = len(history)
        step_x = w / (60 - 1) if count > 0 else 0
        
        points = []
        max_ping = 200 # Fixed scale
        
        for i, ms in enumerate(history):
            if count < 60:
                x = w - ((count - 1 - i) * step_x) 
            else:
                x = i * step_x
            
            val = ms if ms > 0 else 0
            if val > max_ping: val = max_ping
            
            y = h - (val / max_ping * h)
            points.append(x)
            points.append(y)
            
        if len(points) >= 4:
            self.canvas.create_line(points, fill=color, width=2, smooth=True)


class StartupFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        
        ctk.CTkLabel(self, text="STARTUP MANAGER", font=("Roboto", 24, "bold"), text_color="#ffcc00").pack(anchor="w", pady=(0, 20))
        ctk.CTkLabel(self, text="Programs running at startup (User Registry)", font=("Roboto", 12)).pack(anchor="w", pady=(0, 20))
        
        # List
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="#232323")
        self.scroll.pack(fill="both", expand=True, padx=10, pady=10)
        self.items = []
        
        # Controls
        ctrl = ctk.CTkFrame(self, fg_color="transparent")
        ctrl.pack(fill="x", pady=20)
        
        ctk.CTkButton(ctrl, text="Refresh List", fg_color="#3da9fc", command=self.refresh_list).pack(side="left", padx=10)
        ctk.CTkButton(ctrl, text="Delete Selected", fg_color="#ef4565", hover_color="#d93654", command=self.delete_selected).pack(side="right", padx=10)
        
        self.selected_name = None
        
    def update_ui(self, *args):
        self.refresh_list()

    def refresh_list(self):
        for w in self.items: w.destroy()
        self.items = []
        self.selected_name = None
        
        data = self.controller.startup_mgr.get_startup_items()
        
        for name, path in data:
            row = ctk.CTkRadioButton(self.scroll, text=f"{name}  [{path}]", font=("Consolas", 12),
                                     value=name, command=lambda n=name: self.set_sel(n))
            row.pack(fill="x", pady=5, padx=10, anchor="w")
            self.items.append(row)
            
    def set_sel(self, name):
        self.selected_name = name
        
    def delete_selected(self):
        if not self.selected_name:
            ToastNotification.show_toast("Startup Manager", "Please select an item first.", "red")
            return
            
        if self.controller.startup_mgr.delete_item(self.selected_name):
            ToastNotification.show_toast("Success", f"Removed '{self.selected_name}' from startup.", "green")
            self.refresh_list()
        else:
            ToastNotification.show_toast("Error", "Failed to remove item.", "red")


class GameModeFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        self.active = False
        
        ctk.CTkLabel(self, text="GAME BOOSTER MODE", font=("Roboto", 24, "bold"), text_color="#ef4565").pack(anchor="w", pady=(0, 20))
        
        # Hero Section
        hero = ctk.CTkFrame(self, fg_color="#2b2b2b", corner_radius=20)
        hero.pack(fill="x", pady=20, padx=20)
        
        self.lbl_status = ctk.CTkLabel(hero, text="GAMING MODE: OFF", font=("Kanit", 28, "bold"), text_color="gray")
        self.lbl_status.pack(pady=(30, 10))
        
        self.btn_toggle = ctk.CTkButton(hero, text="ACTIVATE", width=200, height=60, 
                                        fg_color="#3da9fc", font=("Kanit", 20, "bold"),
                                        command=self.toggle_mode)
        self.btn_toggle.pack(pady=(10, 30))
        
        # Info
        info = ctk.CTkFrame(self, fg_color="transparent")
        info.pack(fill="x", padx=40)
        
        items = [
            "🚀 Switches to 'Ultimate Performance' Power Plan",
            "⚖️ Enables 'Auto-Balance' for CPU Cores",
            "🎮 Auto-Boosts Active Game Priority (High)",
            "🛡️ Protects Game from RAM Cleaning"
        ]
        
        for i in items:
            ctk.CTkLabel(info, text=i, font=("Kanit", 14), anchor="w").pack(fill="x", pady=5)
            
    def toggle_mode(self):
        self.controller.game_mode_active = not self.controller.game_mode_active
        
        if self.controller.game_mode_active:
            # ON
            self.active = True
            self.lbl_status.configure(text="GAMING MODE: ON", text_color="#ef4565")
            self.btn_toggle.configure(text="DEACTIVATE", fg_color="#ef4565", hover_color="#d93654")
            
            # Apply Optimizations
            self.controller.cpu_mgr.set_power_plan("Ultimate")
            self.controller.cpu_mgr.auto_balance_enabled = True
            self.controller.auto_ram_enabled = True
            self.controller.auto_ram_threshold = 75 # Aggressive
            
            ToastNotification.show_toast("Game Booster Activated", "Foreground Boost Active!", "green")
        else:
            # OFF
            self.active = False
            self.lbl_status.configure(text="GAMING MODE: OFF", text_color="gray")
            self.btn_toggle.configure(text="ACTIVATE", fg_color="#3da9fc", hover_color="#1e90ff")
            
            # Revert
            self.controller.cpu_mgr.set_power_plan("Balanced")
            ToastNotification.show_toast("Game Booster Deactivated", "Returned to normal.", "blue")





if __name__ == "__main__":
    try:
        app = SystemManagerApp()
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"App crashed: {e}")
