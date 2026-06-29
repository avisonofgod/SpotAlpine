#!/usr/bin/env python3
"""
spot-server — Backend binario SP para Alpine.
Protocolo binario, almacenamiento persistente, sin dependencias.
Puerto TCP 1801.
"""
import json, os, struct, time, uuid, socket, select, sys, threading
from pathlib import Path

# ─── Protocolo ───────────────────────────────────────────────

MAGIC = b"SP"
MT = {
    "HANDSHAKE": 1, "HANDSHAKE_OK": 2, "HANDSHAKE_ERR": 3,
    "LIST": 0x10, "GET": 0x11, "CREATE": 0x12, "UPDATE": 0x13, "DELETE": 0x14,
    "PING": 0x30, "PONG": 0x31, "ERROR": 0x40, "BYE": 0xFF,
}
F_REQ, F_RSP, F_ERR = 1, 2, 4

K = {"PATH":1,"ACTION":2,"DATA":4,"ID":5,"TOKEN":6,"VERSION":7,"STATUS":8,
     "MESSAGE":9,"COUNT":10,"NAME":12,"TITLE":0x0E,"USERNAME":0x12,"PASSWORD":0x13}
K_R = {v:k for k,v in K.items()}

def enc_val(v):
    if isinstance(v, bool): return (9, bytes([1 if v else 0]))
    if isinstance(v, int):
        if v < 256: return (1, bytes([v]))
        if v < 65536: return (2, struct.pack(">H", v))
        return (3, struct.pack(">I", v))
    if isinstance(v, str):
        d = v.encode()
        return (5, struct.pack(">H", len(d)) + d)
    if isinstance(v, dict):
        p = b""; n = len(v)
        for kk, vv in v.items():
            kk = kk.upper()
            if kk in K: p += bytes([0, K[kk]])
            else: dk = kk.encode(); p += bytes([1]) + struct.pack(">H", len(dk)) + dk
            td,dv = enc_val(vv); p += bytes([td]) + dv
        return (11, struct.pack(">H", n) + p)
    if isinstance(v, list):
        p = b""; n = len(v)
        for i in v: td,dv = enc_val(i); p += bytes([td]) + dv
        return (10, struct.pack(">H", n) + p)
    return (5, struct.pack(">H", 0))

def dec_val(t, d, o):
    if t == 1: return (d[o], o+1)
    if t == 2: return (struct.unpack(">H", d[o:o+2])[0], o+2)
    if t == 3: return (struct.unpack(">I", d[o:o+4])[0], o+4)
    if t == 5:
        l = struct.unpack(">H", d[o:o+2])[0]; return (d[o+2:o+2+l].decode(), o+2+l)
    if t == 9: return (bool(d[o]), o+1)
    if t == 10:
        c = struct.unpack(">H", d[o:o+2])[0]; o += 2; r = []
        for _ in range(c): tv = d[o]; o += 1; v, o = dec_val(tv, d, o); r.append(v)
        return (r, o)
    if t == 11:
        c = struct.unpack(">H", d[o:o+2])[0]; o += 2; r = {}
        for _ in range(c):
            f = d[o]; o += 1
            if f == 0: k = d[o]; o += 1; n = K_R.get(k, f"k{k}")
            else: l = struct.unpack(">H", d[o:o+2])[0]; o += 2; n = d[o:o+l].decode(); o += l
            t = d[o]; o += 1; v, o = dec_val(t, d, o); r[n] = v
        return (r, o)
    return (None, o)

def mkframe(t, f, p=None):
    p = p or {}; pd = struct.pack(">H", len(p))
    for k,v in p.items():
        k = k.upper()
        if k in K: pd += bytes([0, K[k]])
        else: dk = k.encode(); pd += bytes([1]) + struct.pack(">H", len(dk)) + dk
        td,dv = enc_val(v); pd += bytes([td]) + dv
    l = 6 + len(pd)
    return MAGIC + struct.pack(">H", l) + bytes([t, f]) + pd

def prs(d):
    if len(d) < 6 or d[:2] != MAGIC: raise ValueError("bad frame")
    l = struct.unpack(">H", d[2:4])[0]
    t, f, p = d[4], d[5], {}
    if l > 6:
        pd = d[6:l]; c = struct.unpack(">H", pd[:2])[0]; o = 2
        for _ in range(c):
            fg = pd[o]; o += 1
            if fg == 0: k = pd[o]; o += 1; n = K_R.get(k, f"k{k}")
            else: lk = struct.unpack(">H", pd[o:o+2])[0]; o += 2; n = pd[o:o+lk].decode(); o += lk
            tv = pd[o]; o += 1; v, o = dec_val(tv, pd, o); p[n] = v
    return t, f, p, l

# ─── Servidor ────────────────────────────────────────────────

class SpotServer:
    def __init__(self, host="0.0.0.0", port=1801):
        self.host, self.port = host, port
        self.sessions, self._data = {}, {}
        self._dir = Path(__file__).parent / "data"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._start = time.time()
        self._run = False

    def start(self):
        self._run = True
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port)); s.listen(10); s.setblocking(False)
        print(f"spot-server :{self.port}")
        while self._run:
            r,_,_ = select.select([s], [], [], 0.5)
            if r:
                try:
                    c, a = s.accept()
                    threading.Thread(target=self._h, args=(c,a), daemon=True).start()
                except: pass
        s.close()

    def stop(self): self._run = False

    def _h(self, c, a):
        b, sid = b"", None
        try:
            c.settimeout(30)
            while self._run:
                try: d = c.recv(4096)
                except socket.timeout:
                    if sid: c.sendall(mkframe(MT["PING"], F_REQ))
                    continue
                if not d: break
                b += d
                while len(b) >= 6:
                    if b[:2] != MAGIC: b = b[1:]; continue
                    l = struct.unpack(">H", b[2:4])[0]
                    if len(b) < l: break
                    t,f,p,_ = prs(b[:l]); b = b[l:]
                    r = self._p(t, f, p, sid)
                    if r:
                        if t == MT["HANDSHAKE"] and r[1] == F_RSP: sid = r[2].get("TOKEN")
                        c.sendall(r[0])
                        if t == MT["BYE"]: return
        except: pass
        finally:
            if sid and sid in self.sessions: del self.sessions[sid]
            c.close()

    def _p(self, t, f, p, sid):
        if t == MT["HANDSHAKE"]:
            tok = uuid.uuid4().hex
            self.sessions[tok] = {"exp": time.time() + 86400}
            return (mkframe(MT["HANDSHAKE_OK"], F_RSP, {"TOKEN": tok, "STATUS": 0}), F_RSP, {"TOKEN": tok})
        if t == MT["BYE"]:
            if sid and sid in self.sessions: del self.sessions[sid]
            return (mkframe(MT["BYE"], F_RSP, {"STATUS": 0}), F_RSP, {})
        if not sid or sid not in self.sessions:
            return (mkframe(MT["ERROR"], F_RSP|F_ERR, {"STATUS": 401, "MESSAGE": "no auth"}), F_RSP|F_ERR, {})
        if self.sessions[sid]["exp"] < time.time():
            del self.sessions[sid]
            return (mkframe(MT["ERROR"], F_RSP|F_ERR, {"STATUS": 401, "MESSAGE": "expired"}), F_RSP|F_ERR, {})

        path = p.get("PATH", "")
        action = {MT["LIST"]:"list", MT["GET"]:"list", MT["CREATE"]:"create",
                  MT["UPDATE"]:"update", MT["DELETE"]:"delete"}.get(t, "list")

        if path in ("", "/menus"):
            return (mkframe(t, F_RSP, {"DATA": MENUS, "COUNT": len(MENUS), "STATUS": 0}), F_RSP, {})

        if path in ("/system/info", "/system/identity"):
            return (mkframe(t, F_RSP, {"DATA": self._sysinfo(), "STATUS": 0}), F_RSP, {})

        k = path.strip("/").replace("/", "_")
        if not k: k = "root"
        f = self._dir / f"{k}.json"
        items = json.loads(f.read_text()) if f.exists() else []

        if action == "list":
            return (mkframe(t, F_RSP, {"DATA": items, "COUNT": len(items), "STATUS": 0}), F_RSP, {})
        elif action == "create":
            d = p.get("DATA", {}); d[".id"] = f"*{len(items)+1}"
            items.append(d); f.write_text(json.dumps(items, indent=2))
            return (mkframe(t, F_RSP, {"DATA": d, "COUNT": 1, "STATUS": 0, "MESSAGE": "created"}), F_RSP, {})
        elif action == "update":
            d = p.get("DATA", {}); iid = d.get(".id", "")
            for i, it in enumerate(items):
                if it.get(".id") == iid: items[i].update(d); f.write_text(json.dumps(items, indent=2)); return (mkframe(t, F_RSP, {"DATA": items[i], "STATUS": 0}), F_RSP, {})
            return (mkframe(t, F_RSP, {"STATUS": 404, "MESSAGE": "not found"}), F_RSP, {})
        elif action == "delete":
            d = p.get("DATA", {}); iid = d.get(".id", "")
            for i, it in enumerate(items):
                if it.get(".id") == iid: items.pop(i); f.write_text(json.dumps(items, indent=2)); return (mkframe(t, F_RSP, {"STATUS": 0}), F_RSP, {})
            return (mkframe(t, F_RSP, {"STATUS": 404, "MESSAGE": "not found"}), F_RSP, {})

        return (mkframe(t, F_RSP, {"DATA": [], "STATUS": 0}), F_RSP, {})

    def _sysinfo(self):
        u = time.time() - self._start
        d, h, m = int(u//86400), int(u%86400//3600), int(u%3600//60)
        cl, mt, mf = 23, 512.0, 128.0
        try:
            with open("/proc/loadavg") as f:
                cl = int(float(f.read().split()[0]) * 100 / 4)
            with open("/proc/meminfo") as f:
                for l in f:
                    if l.startswith("MemTotal:"): mt = int(l.split()[1])/1024
                    elif l.startswith("MemAvailable:"): mf = int(l.split()[1])/1024
        except: pass
        return {"identity":"alpine","version":"3.23","uptime":f"{d}d{h}h{m}m",
                "cpu-load":str(min(cl,100)),"free-memory":f"{mf:.0f}MiB","total-memory":f"{mt:.0f}MiB"}

MENUS = [
    {"name":"Dashboard","containers":[{"title":"Dashboard"}]},
    {"name":"Hotspot","containers":[{"title":"Servidores"},{"title":"Perfiles"},{"title":"Activos"},{"title":"Hosts"}]},
    {"name":"Firewall","containers":[{"title":"Filtro"},{"title":"NAT"},{"title":"Mangle"}]},
    {"name":"Interfaces","containers":[{"title":"Interfaces"}]},
    {"name":"Bridge","containers":[{"title":"Bridge"},{"title":"VLANs"}]},
    {"name":"IP","containers":[{"title":"Direcciones"},{"title":"Rutas"},{"title":"DNS"}]},
    {"name":"DHCP","containers":[{"title":"Servidor"},{"title":"Concesiones"}]},
    {"name":"Balanceo","containers":[{"title":"Reglas"},{"title":"Tablas"}]},
    {"name":"PPP","containers":[{"title":"Secretos"},{"title":"Activos"}]},
    {"name":"RADIUS","containers":[{"title":"Servidores"}]},
    {"name":"WireGuard","containers":[{"title":"Interfaces"},{"title":"Peers"}]},
    {"name":"Sistema","containers":[{"title":"Identidad"},{"title":"Recursos"}]},
    {"name":"Log","containers":[{"title":"Log"}]},
]

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=1801)
    p.add_argument("--bind", default="0.0.0.0")
    a = p.parse_args()
    s = SpotServer(host=a.bind, port=a.port)
    try: s.start()
    except KeyboardInterrupt: s.stop()
