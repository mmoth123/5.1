import os
import sys
import time
import zipfile
import shutil
import urllib.request
import subprocess
import ctypes
from tkinter import messagebox
import tkinter as tk

def log_msg(msg):
    print(f"[Updater] {msg}")

def updater_main():
    # Usage: updater.py <download_url> <install_dir> <pid_to_wait> <zip_name>
    if len(sys.argv) < 5:
        log_msg("Invalid arguments.")
        return

    url = sys.argv[1]
    install_dir = sys.argv[2]
    pid_to_wait = int(sys.argv[3])
    zip_name = sys.argv[4]
    
    # Setup simple UI for progress
    root = tk.Tk()
    root.title("System Manager Updater")
    root.geometry("300x150")
    root.eval('tk::PlaceWindow . center')
    
    lbl = tk.Label(root, text="Updating...", font=("Segoe UI", 12))
    lbl.pack(pady=20)
    
    status = tk.StringVar(value="Waiting for app to close...")
    tk.Label(root, textvariable=status).pack(pady=5)
    
    root.update()

    # 1. Wait for PID to close
    log_msg(f"Waiting for PID {pid_to_wait} to close...")
    time.sleep(1) # Give it a second gracefully
    try:
        while ps_exists(pid_to_wait):
            time.sleep(0.5)
            status.set("Waiting for application to close...")
            root.update()
    except:
        pass

    # 2. Download
    status.set("Downloading update...")
    root.update()
    zip_path = os.path.join(install_dir, zip_name)
    
    try:
        log_msg(f"Downloading {url} to {zip_path}")
        urllib.request.urlretrieve(url, zip_path)
    except Exception as e:
        messagebox.showerror("Update Failed", f"Download failed:\n{e}")
        sys.exit(1)

    # 3. Extract and Replace
    status.set("Installing updates...")
    root.update()
    log_msg("Extracting...")
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Extract to a temp folder first to avoid partial overwrites if possible,
            # but for simplicity we extract directly. 
            # CAUTION: We must NOT delete 'secure_data'.
            
            # Get list of files
            for member in zip_ref.namelist():
                # Skip secure_data if it's in the zip (it shouldn't be, but valid safety)
                if member.startswith("secure_data/") or "secure_data/" in member:
                    continue
                
                # We can extract now
                zip_ref.extract(member, install_dir)
                
    except Exception as e:
        messagebox.showerror("Update Error", f"Failed to extract:\n{e}")
        sys.exit(1)
        
    # 4. Cleanup
    try:
        os.remove(zip_path)
    except: pass

    status.set("Done! Restarting...")
    root.update()
    time.sleep(1)
    
    # 5. Restart
    bat_path = os.path.join(install_dir, "RUN_APP.bat")
    if os.path.exists(bat_path):
        subprocess.Popen([bat_path], shell=True, cwd=install_dir)
    else:
         # Fallback to main.py or exe
         main_py = os.path.join(install_dir, "main.py")
         if os.path.exists(main_py):
             subprocess.Popen(["python", main_py], shell=True, cwd=install_dir)
    
    sys.exit(0)

def ps_exists(pid):
    """Check if registry/pid exists using ctypes (windows)."""
    if pid < 0: return False
    # PROCESS_QUERY_INFORMATION (0x0400) or PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if handle:
            exit_code = ctypes.c_ulong()
            kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            kernel32.CloseHandle(handle)
            return exit_code.value == 259 # STILL_ACTIVE = 259
    except: 
        return False
    return False

if __name__ == "__main__":
    try:
        updater_main()
    except Exception as e:
        messagebox.showerror("Critical Error", f"Updater failed: {e}")
