"""
agent/agent.py — FIXED VERSION
Auto-retries connection, tests server before starting, better error messages.
"""
import os, sys, time, math, threading, getpass, datetime, socket, json, argparse
from collections import deque

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    print("[!] Run: pip install requests")
    sys.exit(1)

try:
    from pynput import keyboard, mouse as pmouse
    PYNPUT = True
except ImportError:
    PYNPUT = False
    print("[!] pynput not installed — DEMO mode (fake events)")

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

# ── Args ──────────────────────────────────────────────────────────────────────
ap = argparse.ArgumentParser()
ap.add_argument("--server", default="http://127.0.0.1:5000")
ap.add_argument("--user",   default=getpass.getuser())
ap.add_argument("--window", default=30, type=int)
args = ap.parse_args()

SERVER_URL     = args.server.rstrip("/")
USERNAME       = args.user
SESSION_WINDOW = args.window
HOSTNAME       = socket.gethostname()
try:
    MACHINE_IP = socket.gethostbyname(socket.gethostname())
except Exception:
    MACHINE_IP = "unknown"

SUSPICIOUS_PROCS = {
    "mimikatz.exe","psexec.exe","pwdump.exe","procdump.exe",
    "cmd.exe","powershell.exe","wmic.exe","net.exe",
    "reg.exe","certutil.exe","bitsadmin.exe","schtasks.exe",
}
SENSITIVE_PATHS = [
    "\\windows\\system32\\config","password","passwd","credentials",
    "secret","salary","payroll","confidential","private","id_rsa",".ssh","ntds","sam",
]

lock            = threading.Lock()
key_press_times = {}
dwell_buf       = deque()
flight_buf      = deque()
last_release    = [None]
mouse_buf       = deque(maxlen=1000)
click_buf       = deque()
session_count   = [0]
failed_logins   = [0]

# ── Input hooks ───────────────────────────────────────────────────────────────
def on_press(key):
    t = time.time() * 1000
    with lock: key_press_times[str(key)] = t

def on_release(key):
    t = time.time() * 1000
    with lock:
        k = str(key)
        if k in key_press_times: dwell_buf.append(t - key_press_times.pop(k))
        if last_release[0] is not None:
            flight = t - last_release[0]
            if 0 < flight < 3000: flight_buf.append(flight)
        last_release[0] = t

def on_move(x, y):
    with lock: mouse_buf.append((time.time(), x, y))

def on_click(x, y, button, pressed):
    if pressed:
        with lock: click_buf.append(time.time())

def scan_procs():
    if not PSUTIL: return []
    found = []
    try:
        for p in psutil.process_iter(['name','pid']):
            try:
                if (p.info['name'] or '').lower() in {x.lower() for x in SUSPICIOUS_PROCS}:
                    found.append({"name":p.info['name'],"pid":p.info['pid']})
            except Exception: pass
    except Exception: pass
    return found

def scan_files():
    if not PSUTIL: return []
    hits = []
    try:
        for p in psutil.process_iter(['name']):
            try:
                for f in p.open_files():
                    if any(k in f.path.lower() for k in SENSITIVE_PATHS):
                        hits.append({"process":p.info['name'],"file":f.path[:100]})
            except Exception: pass
    except Exception: pass
    return hits[:5]

def mean(l): return sum(l)/len(l) if l else 0.0

def compute_window():
    with lock:
        dwells  = list(dwell_buf);  dwell_buf.clear()
        flights = list(flight_buf); flight_buf.clear()
        clicks  = list(click_buf);  click_buf.clear()
        moves   = list(mouse_buf);  mouse_buf.clear()

    speeds = []
    for i in range(1, len(moves)):
        t1,x1,y1 = moves[i-1]; t2,x2,y2 = moves[i]
        dt = t2-t1
        if dt > 0.001:
            speeds.append(math.sqrt((x2-x1)**2+(y2-y1)**2)/dt)

    sys_cpu = psutil.cpu_percent(interval=None) if PSUTIL else 0
    sys_mem = psutil.virtual_memory().percent   if PSUTIL else 0
    hour    = datetime.datetime.now().hour

    return {
        "user_id":           USERNAME,
        "hostname":          HOSTNAME,
        "machine_ip":        MACHINE_IP,
        "session_id":        f"SES{session_count[0]:04d}",
        "timestamp":         datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "keystroke_latency": round(mean(dwells),  2),
        "flight_time":       round(mean(flights), 2),
        "mouse_speed":       round(mean(speeds),  2),
        "click_rate":        len(clicks),
        "key_count":         len(dwells),
        "session_duration":  SESSION_WINDOW,
        "login_frequency":   1,
        "cpu_usage":         sys_cpu,
        "memory_usage":      sys_mem,
        "failed_logins":     failed_logins[0],
        "after_hours":       1 if (hour < 7 or hour >= 20) else 0,
        "suspicious_procs":  scan_procs(),
        "sensitive_files":   scan_files(),
        "hour":              hour,
    }

# ── Connection test ───────────────────────────────────────────────────────────
def test_connection():
    """Test if server is reachable before starting. Returns True/False."""
    print(f"\n[*] Testing connection to {SERVER_URL} ...")
    try:
        r = requests.get(f"{SERVER_URL}/api/ping", timeout=5)
        if r.status_code == 200:
            print(f"[✓] Server reachable! Response: {r.json()}")
            return True
        else:
            print(f"[!] Server responded with status {r.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"[✗] Connection REFUSED — server not running or wrong IP/port")
        return False
    except requests.exceptions.Timeout:
        print(f"[✗] Connection TIMED OUT — firewall may be blocking port 5000")
        return False
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False

def register_with_server():
    try:
        r = requests.post(f"{SERVER_URL}/api/register",
            json={"user_id":USERNAME,"hostname":HOSTNAME,"ip":MACHINE_IP}, timeout=5)
        if r.status_code == 200:
            print(f"[✓] Registered with server as '{USERNAME}'")
            return True
    except Exception as e:
        print(f"[!] Registration failed: {e}")
    return False

def send(data):
    try:
        r = requests.post(f"{SERVER_URL}/api/ingest", json=data, timeout=10)
        if r.status_code == 200:
            resp  = r.json()
            score = resp.get("risk_score", 0)
            lv    = resp.get("risk_level",  "Low")
            col   = "\033[91m" if score>70 else "\033[93m" if score>40 else "\033[92m"
            print(f"[{data['timestamp']}] Sent OK  Score:{col}{score}\033[0m/100 [{lv}]"
                  f"  keys={data['key_count']}  clicks={data['click_rate']}"
                  f"  sus={len(data['suspicious_procs'])}")
            return True
        else:
            print(f"[!] Server error {r.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"[!] Lost connection to server — will retry next window")
        return False
    except Exception as e:
        print(f"[!] Send error: {e}")
        return False

def demo_loop():
    import random
    while True:
        with lock:
            for _ in range(random.randint(40, 120)):
                dwell_buf.append(random.gauss(145, 25))
                flight_buf.append(random.gauss(95,  18))
                click_buf.append(time.time())
                mouse_buf.append((time.time(), random.randint(0,1920), random.randint(0,1080)))
        time.sleep(8)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{'='*52}")
    print(f"  INSIDERSHIELD AGENT  v1.1 FIXED")
    print(f"  User    : {USERNAME}")
    print(f"  Machine : {HOSTNAME} ({MACHINE_IP})")
    print(f"  Server  : {SERVER_URL}")
    print(f"  Window  : {SESSION_WINDOW}s")
    print(f"{'='*52}")

    # ── Step 1: Test connection ────────────────────────────────────────────
    connected = test_connection()
    if not connected:
        print(f"""
╔══════════════════════════════════════════════════════╗
║  CONNECTION FAILED — TROUBLESHOOTING:               ║
║                                                      ║
║  1. Make sure START_SERVER.bat is running on PC1     ║
║     and shows "Running on http://0.0.0.0:5000"       ║
║                                                      ║
║  2. Check the correct IP — on Dashboard PC run:      ║
║     ipconfig                                         ║
║     Look for IPv4 under WiFi (not 127.0.0.1)         ║
║                                                      ║
║  3. Add firewall rule on Dashboard PC (run as Admin):║
║     netsh advfirewall firewall add rule              ║
║     name="InsiderShield" dir=in action=allow         ║
║     protocol=TCP localport=5000                      ║
║                                                      ║
║  4. Test from this PC browser:                       ║
║     http://{SERVER_URL.replace('http://','').ljust(20)}        ║
║     If page opens → re-run agent                     ║
╚══════════════════════════════════════════════════════╝

Retrying every 10 seconds...
""")
        # Keep retrying instead of quitting
        while not connected:
            time.sleep(10)
            print(f"[*] Retrying {SERVER_URL} ...")
            connected = test_connection()

    # ── Step 2: Register ──────────────────────────────────────────────────
    register_with_server()

    # ── Step 3: Start listeners ───────────────────────────────────────────
    if PYNPUT:
        keyboard.Listener(on_press=on_press, on_release=on_release).start()
        pmouse.Listener(on_move=on_move, on_click=on_click).start()
        print(f"[✓] Keyboard + Mouse capture ACTIVE")
    else:
        threading.Thread(target=demo_loop, daemon=True).start()
        print(f"[!] DEMO mode (pynput not installed)")

    print(f"[✓] Process scanner ACTIVE")
    print(f"[✓] Sending to dashboard every {SESSION_WINDOW}s")
    print(f"\nMinimize this window and work normally.")
    print(f"To test: open cmd.exe, type wrong passwords, etc.\n")

    # ── Step 4: Main loop ─────────────────────────────────────────────────
    while True:
        time.sleep(SESSION_WINDOW)
        data = compute_window()
        if not send(data):
            # Try re-registering on next failure
            time.sleep(5)
            register_with_server()
        session_count[0] += 1

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Agent stopped]")
