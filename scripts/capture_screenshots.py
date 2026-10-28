"""
Agni (अग्नि) - Automated Screenshot Capture Script
File: scripts/capture_screenshots.py

Spins up backend and frontend servers, populates demo APT telemetry,
and captures full HD 1920x1080 screenshots of core SOC views using headless Chrome.
"""

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ASSETS_DIR = os.path.join(PROJECT_ROOT, "docs", "assets")
BACKEND_URL = "http://127.0.0.1:8000"
FRONTEND_URL = "http://localhost:5173"

SCREENSHOTS = [
    ("overview.png", "http://localhost:5173/#/overview"),
    ("live-events.png", "http://localhost:5173/#/events"),
    ("incidents.png", "http://localhost:5173/#/incidents"),
    ("file-integrity.png", "http://localhost:5173/#/fim"),
    ("network-intel.png", "http://localhost:5173/#/network"),
]


def wait_for_url(url: str, timeout: int = 30) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Agni-Capture"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status in (200, 304):
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main():
    os.makedirs(ASSETS_DIR, exist_ok=True)

    print("[*] Starting backend uvicorn on port 8000...")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(PROJECT_ROOT, "backend")
    
    backend_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
            "--app-dir",
            os.path.join(PROJECT_ROOT, "backend"),
        ],
        cwd=PROJECT_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    print("[*] Starting frontend server on port 5173...")
    frontend_proc = subprocess.Popen(
        ["npx", "vite", "preview", "--port", "5173"],
        cwd=os.path.join(PROJECT_ROOT, "frontend"),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        print("[*] Waiting for backend at http://127.0.0.1:8000/api/v1/health...")
        if not wait_for_url("http://127.0.0.1:8000/api/v1/health", timeout=25):
            raise RuntimeError("Backend failed to start within timeout.")
        print("[+] Backend is ready.")

        print("[*] Waiting for frontend at http://localhost:5173/...")
        if not wait_for_url("http://localhost:5173/", timeout=25):
            raise RuntimeError("Frontend failed to start within timeout.")
        print("[+] Frontend is ready.")

        # Seed sample scenario
        print("[*] Generating APT intrusion scenario telemetry...")
        seed_url = f"{BACKEND_URL}/api/v1/telemetry/sample-events/generate?scenario=apt_intrusion"
        req = urllib.request.Request(seed_url, data=b"", method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[+] Sample data seeded: HTTP {resp.status}")

        # Small pause for cache/db synchronization
        time.sleep(2)

        for filename, target_url in SCREENSHOTS:
            out_path = os.path.join(ASSETS_DIR, filename)
            print(f"[*] Capturing {filename} from {target_url}...")

            cmd = [
                CHROME_PATH,
                "--headless=new",
                f"--screenshot={out_path}",
                "--window-size=1920,1080",
                "--hide-scrollbars",
                "--disable-gpu",
                "--virtual-time-budget=6000",
                target_url,
            ]
            subprocess.run(cmd, check=True, timeout=20)

            if not os.path.exists(out_path):
                raise RuntimeError(f"Screenshot file not created: {out_path}")
            size = os.path.getsize(out_path)
            if size == 0:
                raise RuntimeError(f"Screenshot file is 0 bytes: {out_path}")
            print(f"[+] Captured {filename} ({size:,} bytes).")

    finally:
        print("[*] Cleaning up background server processes...")
        try:
            backend_proc.terminate()
            backend_proc.wait(timeout=3)
        except Exception:
            backend_proc.kill()

        try:
            # On Windows shell=True spawns cmd.exe, so taskkill the tree
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(frontend_proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass
        print("[+] Servers stopped.")


if __name__ == "__main__":
    main()
