import os
import time
import shutil
from pathlib import Path

SOURCE_PATH = r"\\10.1.1.3\i\Developer\frontear\webshell\payload.py"
DEST_PATH = r"D:\frontear\ffs\payload.py"

def copy_payload():
    try:
        shutil.copy2(SOURCE_PATH, DEST_PATH)
        print(f"[+] Successfully copied payload at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    except FileNotFoundError:
        print(f"[-] Source file not found: {SOURCE_PATH}")
    except PermissionError:
        print(f"[-] Permission denied while copying file")
    except Exception as e:
        print(f"[-] Error copying file: {str(e)}")

def main():
    print("[*] Starting payload update service...")
    while True:
        copy_payload()
        time.sleep(11)  # Wait for 1 minute

if __name__ == "__main__":
    main() 