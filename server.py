"""
server/server.py — FIXED: listens on 0.0.0.0, shows correct IP
"""
import os, sys, json, datetime, threading, socket
from collections import defaultdict, deque
from flask import Flask, jsonify, render_template, request

BASE = os.path.dirname(os.path.abspath(__file__))
TMPL = os.path.join(BASE, "templates")
OUT  = os.path.join(BASE, "output")
os.makedirs(OUT, exist_ok=True)

app  = Flask(__name__, template_folder=TMPL)
lock = threading.Lock()

users          = {}
user_sessions  = defaultdict(list)
user_events    = defaultdict(lambda: deque(maxlen=100))
global_events  = deque(maxlen=300)
registered_pcs = {}
baselines      = defaultdict(lambda: {"dwell": None, "history": deque(maxlen=8)})

SUSPICIOUS_PROCS = {
    "mimikatz.exe","psexec.exe","pwdump.exe","procdump.exe",
    "cmd.exe","powershell.exe","wmic.exe","net.exe",
    "reg.exe","certutil.exe","bitsadmin.exe","schtasks.exe",
}
SENSITIVE_PATHS = ["password","passwd","credentials","secret","salary",
                   "payroll","confidential","id_rsa","ntds","sam"]
MITRE = {
    "mimikatz.exe":  ("T1003","Credential Dumping","CRITICAL"),
    "psexec.exe":    ("T1021","Lateral Movement","HIGH"),
    "powershell.exe":("T1059","Command Execution","MEDIUM"),
    "cmd.exe":       ("T1059","Command Execution","MEDIUM"),
    "net.exe":       ("T1098","Account Manipulation","HIGH"),
    "reg.exe":       ("T1112","Registry Modification","HIGH"),
    "wmic.exe":      ("T1082","System Discovery","MEDIUM"),
    "certutil.exe":  ("T1132","Data Encoding","HIGH"),
    "schtasks.exe":  ("T1053","Scheduled Task","HIGH"),
}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except: return "127.0.0.1"

def level(score):
    return "Critical" if score>=80 else "High" if score>=60 else "Medium" if score>=35 else "Low"

def log_event(msg, sev="INFO", uid="SYSTEM"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    with lock: global_events.appendleft({"time":ts,"msg":msg,"severity":sev,"user_id":uid})

def score_session(uid, data):
    score, reasons, evts, mitre_hits = 0, [], [], []
    bl = baselines[uid]
    def e(msg,sev): return {"time":datetime.datetime.now().strftime("%H:%M:%S"),"msg":msg,"severity":sev}

    dwell = data.get("keystroke_latency",0)
    if dwell>0 and bl["dwell"] and bl["dwell"]>0:
        drift = abs(dwell-bl["dwell"])/bl["dwell"]
        if drift>0.5:
            score+=min(25,drift*20); reasons.append(f"Typing changed {round(drift*100)}% from baseline")
            evts.append(e(f"Keystroke drift {round(drift*100)}% — {uid}","MEDIUM"))
    if 0<dwell<60:
        score+=20; reasons.append(f"Very fast typing ({dwell}ms)"); evts.append(e(f"Fast typing by {uid}","HIGH"))
    if data.get("mouse_speed",0)>800:
        score+=15; reasons.append(f"Erratic mouse ({round(data['mouse_speed'])}px/s)")
    if data.get("after_hours",0):
        score+=20; h=data.get("hour",0); reasons.append(f"After-hours at {h:02d}:xx")
        evts.append(e(f"After-hours ({h:02d}:xx) — {uid}","HIGH"))
    fl=data.get("failed_logins",0)
    if fl>0:
        score+=min(30,fl*10); reasons.append(f"{fl} failed login(s)")
        evts.append(e(f"{fl} failed login(s) — {uid}","HIGH"))
    for p in data.get("suspicious_procs",[]):
        nm=p.get("name",""); nl=nm.lower()
        if nl in {x.lower() for x in SUSPICIOUS_PROCS}:
            boost=40 if nl in {"mimikatz.exe","psexec.exe","pwdump.exe"} else 25 if nl in {"wmic.exe","net.exe","reg.exe","certutil.exe"} else 15
            score+=boost; reasons.append(f"Suspicious process: {nm}")
            sev2="CRITICAL" if boost==40 else "HIGH"
            evts.append(e(f"{'🚨 CRITICAL' if sev2=='CRITICAL' else '⚠'}: {nm} — {uid}",sev2))
            if nl in MITRE:
                tid,tname,tsev=MITRE[nl]; mitre_hits.append({"process":nm,"id":tid,"tactic":tname,"severity":tsev})
    for sf in data.get("sensitive_files",[]):
        fn=sf.get("file","")
        if any(k in fn.lower() for k in SENSITIVE_PATHS):
            score+=20; reasons.append(f"Sensitive file: {fn[:50]}")
            evts.append(e(f"📁 Sensitive file — {uid}: {fn[:50]}","HIGH"))
    if data.get("cpu_usage",0)>85: score+=10; reasons.append(f"CPU spike: {data['cpu_usage']}%")
    if dwell>0:
        bl["history"].append(dwell)
        if len(bl["history"])>=3: bl["dwell"]=sum(bl["history"])/len(bl["history"])
    return min(100,round(score,1)), level(min(100,round(score,1))), reasons, mitre_hits, evts

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/api/ping")
def ping(): return jsonify({"status":"ok","time":datetime.datetime.now().strftime("%H:%M:%S")})

@app.route("/api/register", methods=["POST"])
def register():
    d=request.json or {}; uid=d.get("user_id","unknown")
    with lock:
        registered_pcs[uid]={"hostname":d.get("hostname",""),"ip":d.get("ip",""),
            "last_seen":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"status":"online"}
        if uid not in users:
            users[uid]={"user_id":uid,"risk_score":0,"risk_level":"Low","anomaly_flag":0,
                "label":"normal","failed_logins":0,"after_hours_count":0,"sus_proc_count":0,
                "hostname":d.get("hostname",""),"machine_ip":d.get("ip",""),
                "last_seen":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"reasons":[],"mitre_hits":[]}
    log_event(f"🟢 {uid} connected from {d.get('hostname','')} ({d.get('ip','')})")
    print(f"[REGISTER] {uid} @ {d.get('ip','')}")
    return jsonify({"ok":True})

@app.route("/api/ingest", methods=["POST"])
def ingest():
    data=request.json or {}; uid=data.get("user_id","unknown")
    ts=data.get("timestamp",datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    score,lv,reasons,mitre_hits,evts=score_session(uid,data)
    sess={"session_id":data.get("session_id",""),"timestamp":ts,"risk_score":score,"risk_level":lv,
        "reasons":reasons,"mitre_hits":mitre_hits,"keystroke_latency":data.get("keystroke_latency",0),
        "flight_time":data.get("flight_time",0),"mouse_speed":data.get("mouse_speed",0),
        "click_rate":data.get("click_rate",0),"key_count":data.get("key_count",0),
        "cpu_usage":data.get("cpu_usage",0),"failed_logins":data.get("failed_logins",0),
        "after_hours":data.get("after_hours",0),
        "sus_procs":[p["name"] for p in data.get("suspicious_procs",[])],
        "sens_files":[f["file"][:60] for f in data.get("sensitive_files",[])],
        "hostname":data.get("hostname",""),"machine_ip":data.get("machine_ip","")}
    with lock:
        prev=users.get(uid,{}).get("risk_score",0)
        bl=round(0.6*score+0.4*prev,1); bll=level(bl)
        users[uid]={"user_id":uid,"risk_score":bl,"risk_level":bll,"anomaly_flag":1 if bl>=50 else 0,
            "label":"malicious" if bl>=60 else "normal","failed_logins":data.get("failed_logins",0),
            "after_hours_count":data.get("after_hours",0),"sus_proc_count":len(data.get("suspicious_procs",[])),
            "hostname":data.get("hostname",""),"machine_ip":data.get("machine_ip",""),
            "last_seen":ts,"reasons":reasons,"mitre_hits":mitre_hits}
        user_sessions[uid].append(sess)
        if len(user_sessions[uid])>50: user_sessions[uid]=user_sessions[uid][-50:]
        for ev in evts:
            ev["user_id"]=uid; user_events[uid].appendleft(ev); global_events.appendleft(ev)
        if uid in registered_pcs: registered_pcs[uid]["last_seen"]=ts; registered_pcs[uid]["status"]="online"
    print(f"[DATA] {uid} → {bl}/100 [{bll}]  keys={data.get('key_count',0)}  sus={len(data.get('suspicious_procs',[]))}")
    return jsonify({"ok":True,"user_id":uid,"risk_score":bl,"risk_level":bll})

@app.route("/api/trigger", methods=["POST"])
def trigger():
    d=request.json or {}; uid=d.get("user_id",""); etype=d.get("type","failed_login")
    ts=datetime.datetime.now().strftime("%H:%M:%S")
    boosts={"failed_login":(15,f"🔑 Failed login — {uid}","HIGH"),
            "sensitive_file":(20,f"📁 Sensitive file — {uid}","HIGH"),
            "suspicious_proc":(25,f"💻 Suspicious process — {uid}","HIGH"),
            "after_hours":(20,f"🌙 After-hours — {uid}","HIGH"),
            "usb":(15,f"🔌 USB inserted — {uid}","HIGH")}
    boost,msg,sev=boosts.get(etype,(10,f"⚠ Event — {uid}","HIGH"))
    with lock:
        if uid in users:
            ns=min(100,users[uid]["risk_score"]+boost)
            users[uid]["risk_score"]=round(ns,1); users[uid]["risk_level"]=level(ns)
            users[uid]["anomaly_flag"]=1 if ns>=50 else 0; users[uid]["label"]="malicious" if ns>=60 else "normal"
        ev={"time":ts,"msg":msg,"severity":sev,"user_id":uid}
        user_events[uid].appendleft(ev); global_events.appendleft(ev)
    return jsonify({"ok":True})

@app.route("/api/trigger_demo", methods=["POST"])
def trigger_demo():
    demo=[
        {"user_id":"jsmith","hostname":"WS-JSMITH","ip":"192.168.1.101","keystroke_latency":82,
         "mouse_speed":620,"click_rate":45,"key_count":180,"failed_logins":4,"after_hours":1,
         "cpu_usage":72,"flight_time":70,"suspicious_procs":[{"name":"cmd.exe","pid":4321}],
         "sensitive_files":[{"file":"\\\\server\\finance\\payroll.xlsx","process":"explorer.exe"}],
         "session_duration":30,"login_frequency":1,"hour":23,"session_id":"SIM001","machine_ip":"192.168.1.101"},
        {"user_id":"devops1","hostname":"WS-DEVOPS","ip":"10.0.0.55","keystroke_latency":195,
         "mouse_speed":18,"click_rate":6,"key_count":90,"failed_logins":7,"after_hours":0,
         "cpu_usage":91,"flight_time":140,"suspicious_procs":[{"name":"mimikatz.exe","pid":1337},{"name":"powershell.exe","pid":2001}],
         "sensitive_files":[{"file":"C:\\Windows\\System32\\config\\SAM","process":"powershell.exe"}],
         "session_duration":30,"login_frequency":1,"hour":14,"session_id":"SIM002","machine_ip":"10.0.0.55"},
        {"user_id":"mwilson","hostname":"WS-MWILSON","ip":"10.0.0.23","keystroke_latency":148,
         "mouse_speed":31,"click_rate":12,"key_count":410,"failed_logins":0,"after_hours":0,
         "cpu_usage":28,"flight_time":95,"suspicious_procs":[],"sensitive_files":[],
         "session_duration":30,"login_frequency":1,"hour":10,"session_id":"SIM003","machine_ip":"10.0.0.23"},
        {"user_id":"klee","hostname":"WS-KLEE","ip":"10.0.0.31","keystroke_latency":155,
         "mouse_speed":28,"click_rate":9,"key_count":310,"failed_logins":0,"after_hours":0,
         "cpu_usage":22,"flight_time":101,"suspicious_procs":[],"sensitive_files":[],
         "session_duration":30,"login_frequency":1,"hour":11,"session_id":"SIM004","machine_ip":"10.0.0.31"},
    ]
    results=[]
    for u in demo:
        uid2=u["user_id"]
        with lock:
            registered_pcs[uid2]={"hostname":u["hostname"],"ip":u["ip"],
                "last_seen":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"status":"online"}
        sc,lv,reasons,mitre_hits,evts=score_session(uid2,u)
        ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with lock:
            users[uid2]={"user_id":uid2,"risk_score":sc,"risk_level":lv,"anomaly_flag":1 if sc>=50 else 0,
                "label":"malicious" if sc>=60 else "normal","failed_logins":u["failed_logins"],
                "after_hours_count":u["after_hours"],"sus_proc_count":len(u["suspicious_procs"]),
                "hostname":u["hostname"],"machine_ip":u["ip"],"last_seen":ts,"reasons":reasons,"mitre_hits":mitre_hits}
            sess={**u,"timestamp":ts,"risk_score":sc,"risk_level":lv,"reasons":reasons,"mitre_hits":mitre_hits,
                "sus_procs":[p["name"] for p in u["suspicious_procs"]],"sens_files":[f["file"][:60] for f in u["sensitive_files"]]}
            user_sessions[uid2].append(sess)
            for ev in evts:
                ev["user_id"]=uid2; user_events[uid2].appendleft(ev); global_events.appendleft(ev)
        results.append({"user_id":uid2,"score":sc,"level":lv})
    return jsonify({"ok":True,"users":results})

@app.route("/")
def index(): return render_template("dashboard.html")

@app.route("/api/snapshot")
def snapshot():
    with lock:
        return jsonify({"users":list(users.values()),"global_events":list(global_events)[:60],
            "registered_pcs":registered_pcs,"total_users":len(users),
            "flagged_users":sum(1 for u in users.values() if u.get("anomaly_flag")),
            "risk_distribution":{"Low":sum(1 for u in users.values() if u.get("risk_level")=="Low"),
                "Medium":sum(1 for u in users.values() if u.get("risk_level")=="Medium"),
                "High":sum(1 for u in users.values() if u.get("risk_level")=="High"),
                "Critical":sum(1 for u in users.values() if u.get("risk_level")=="Critical")},
            "last_updated":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

@app.route("/api/user/<uid>")
def user_detail(uid):
    with lock:
        return jsonify({"info":users.get(uid,{}),"sessions":user_sessions.get(uid,[])[-20:],
            "events":list(user_events.get(uid,[]))[:30]})

if __name__=="__main__":
    ip=get_local_ip()
    print(f"\n{'='*58}")
    print(f"  INSIDERSHIELD SERVER — FIXED")
    print(f"  Dashboard : http://localhost:5000")
    print(f"  Agent URL : http://{ip}:5000  ← USE THIS IN AGENT")
    print(f"{'='*58}")
    log_event("Server started","INFO")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
