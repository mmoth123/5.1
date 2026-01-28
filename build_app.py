
import os
import subprocess
import sys
from PIL import Image

def build():
    print("--- 1. Converting Icon ---")
    try:
        img = Image.open("app_icon.png")
        img.save("app_icon.ico", format='ICO', sizes=[(256, 256)])
        print("Icon converted to app_icon.ico")
    except Exception as e:
        print(f"Error converting icon: {e}")
        return

    print("\n--- 2. Running PyInstaller ---")
    # specific command to include customtkinter
    # we need to find where customtkinter is installed to add it as data if needed, 
    # but usually collect_all works or the hook works.
    # PyInstaller usually handles customtkinter well with recent versions.
    
    cmd = [
        "pyinstaller",
        "--noconsole",
        "--onedir",
        "--name=System Manager V5.0",
        "--icon=app_icon.ico",
        "--clean",
        "--add-data", f"{os.path.join(os.path.dirname(sys.executable), 'Lib/site-packages/customtkinter')};customtkinter",
        "main.py"
    ]
    
    # Simple attempt first, if ctk fails we add the explicit data path
    # Actually, let's just use --collect-all customtkinter
    cmd = [
        "pyinstaller",
        "--noconsole",
        "--onedir",
        "--name=System Manager V5.0",
        "--icon=app_icon.ico",
        "--clean",
        "--collect-all", "customtkinter",
        "main.py"
    ]
    
    print(f"Executing: {' '.join(cmd)}")
    try:
        subprocess.check_call(cmd)
    except FileNotFoundError:
        print("'pyinstaller' command not found. Trying 'python -m PyInstaller'...")
        cmd[0] = sys.executable
        cmd.insert(1, "-m")
        cmd.insert(2, "PyInstaller")
        print(f"Executing fallback: {' '.join(cmd)}")
        subprocess.check_call(cmd)
    
    print("\n--- DONE ---")
    print(f"Build available in: {os.path.abspath('dist/System Manager V5.0')}")

if __name__ == "__main__":
    build()
