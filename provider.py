"""TrueNAS integration for Hisho (see addon.yaml). Runs inside Core. Read only.

TrueNAS 25.x speaks JSON-RPC 2.0 over a websocket at ``wss://<host>/api/current`` (its REST API is
deprecated). Hisho logs in with an API key, calls only the read methods in ``READ_METHODS``, and keeps
only the fields it shows: pools, disks, alerts, SMB shares and the services behind them.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import time
from typing import Any

READ_METHODS = frozenset({"auth.me", "api_key.query", "system.info", "pool.query", "disk.query", "disk.temperatures", "alert.list",
                          "sharing.smb.query", "sharing.nfs.query", "service.query"})
DISK_WARN_C = 50      # a hard drive above this is too warm (most are rated to 60 C)
POOL_FULL = 0.85      # ZFS slows down and fragments past ~80-90% full
SCRUB_DAYS = 35       # TrueNAS scrubs every 35 days by default


class TrueNASError(RuntimeError):
    pass


# ── a minimal websocket (RFC 6455) client, enough for JSON-RPC text frames ──

def _fp(value: str | None) -> str:
    return str(value or "").replace(":", "").strip().lower()


def server_fingerprint(host: str, port: int = 443) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=8) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
        digest = hashlib.sha256(tls.getpeercert(binary_form=True) or b"").hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


class _WS:
    def __init__(self, host: str, port: int, fingerprint: str | None, timeout: float = 15):
        ctx = ssl.create_default_context()
        if fingerprint:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # checked below by fingerprint
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
            self.sock = ctx.wrap_socket(raw, server_hostname=host)
        except ssl.SSLCertVerificationError:
            raise TrueNASError(f"{host}'s certificate isn't publicly trusted; press Test to pin it")
        except OSError as exc:
            raise TrueNASError(f"can't reach {host}:{port} ({exc})")
        if fingerprint and hashlib.sha256(self.sock.getpeercert(binary_form=True) or b"").hexdigest() != _fp(fingerprint):
            self.sock.close()
            raise TrueNASError(f"{host}'s certificate changed since it was pinned; Hisho won't send the key. "
                               "If you replaced it on purpose, clear the fingerprint and press Test.")
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET /api/current HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise TrueNASError(f"{host} closed the connection during the websocket handshake")
            head += chunk
        status = head.split(b"\r\n", 1)[0].decode(errors="replace")
        if " 101 " not in status + " ":
            raise TrueNASError(f"{host} has no TrueNAS websocket API at /api/current ({status}); is it TrueNAS 25.04+?")
        self.buf = head.split(b"\r\n\r\n", 1)[1]

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise TrueNASError("TrueNAS closed the connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _send(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        n = len(payload)
        head = bytes([0x80 | opcode]) + (bytes([0x80 | n]) if n < 126 else
                                          bytes([0x80 | 126]) + struct.pack("!H", n) if n < 65536 else
                                          bytes([0x80 | 127]) + struct.pack("!Q", n))
        self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def send_text(self, text: str) -> None:
        self._send(0x1, text.encode())

    def recv_text(self) -> str:
        parts: list[bytes] = []
        while True:
            b1, b2 = self._read(2)
            n = b2 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._read(8))[0]
            mask = self._read(4) if b2 & 0x80 else b""
            data = self._read(n)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            op = b1 & 0x0F
            if op == 0x9:          # ping
                self._send(0xA, data)
                continue
            if op == 0x8:          # close
                raise TrueNASError("TrueNAS closed the connection")
            if op in (0x1, 0x2, 0x0):
                parts.append(data)
                if b1 & 0x80:
                    return b"".join(parts).decode()

    def close(self) -> None:
        try:
            self._send(0x8, b"")
        except OSError:
            pass
        self.sock.close()


class Session:
    """One logged-in connection. Only READ_METHODS can be called."""

    def __init__(self, entry: dict[str, Any], key: str, timeout: float = 15):
        host, port = address(entry)
        self.ws = _WS(host, port, entry.get("fingerprint"), timeout)
        self.n = 0
        try:
            if self._call("auth.login_with_api_key", [key]) is not True:
                raise TrueNASError("TrueNAS refused the API key (wrong, revoked, or for another user)")
        except Exception:
            self.ws.close()
            raise

    def _call(self, method: str, params: list[Any]) -> Any:
        self.n += 1
        self.ws.send_text(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            msg = json.loads(self.ws.recv_text())
            if msg.get("id") != self.n:
                continue  # an event or notification, not our answer
            if "error" in msg:
                err = msg["error"] or {}
                data = err.get("data") or {}
                if err.get("code") == -32601 or data.get("errname") == "ENOMETHOD":
                    raise TrueNASError(f"this TrueNAS has no {method}")
                raise TrueNASError(f"{method}: {data.get('reason') or err.get('message') or err}"[:200])
            return msg.get("result")
        raise TrueNASError(f"{method}: no answer in 30 s")

    def call(self, method: str, *params: Any) -> Any:
        if method not in READ_METHODS:
            raise TrueNASError(f"{method} is not on Hisho's read-only list")
        return self._call(method, list(params))

    def close(self) -> None:
        self.ws.close()


# ── sign in once: Hisho makes its own read-only user and API key ─────────

#: What the one-time admin session may call: sign in, find the read-only admin group and the names in use, make
#: Hisho's user and key.
CONNECT_METHODS = frozenset({"auth.login_ex", "auth.login", "privilege.query", "user.query", "group.query",
                             "user.create", "api_key.query", "api_key.create"})
#: What Remove from TrueNAS may call: sign in, look up, and delete the key and user Sign in once made.
DISCONNECT_METHODS = frozenset({"auth.login_ex", "auth.login", "user.query", "api_key.query", "api_key.delete",
                                "user.delete"})


def _machine() -> str:
    """This machine's name for the names Hisho makes (lower-case letters, digits and dashes)."""
    try:
        from hisho import fleet_config
        name = fleet_config.local_name()
    except Exception:  # noqa: BLE001
        name = socket.gethostname()
    return re.sub(r"[^a-z0-9-]+", "-", str(name).split(".")[0].lower()).strip("-")[:20].strip("-") or "hisho"


def _free(base: str, taken: set[str]) -> str:
    """``base``, or ``base-2``, ``base-3``... the first one not in ``taken`` (an existing name is never reused)."""
    name, n = base, 2
    while name in taken:
        name, n = f"{base}-{n}", n + 1
    return name


class AdminSession(Session):
    """Signed in with the admin login the owner typed. The password goes over the pinned TLS connection once and
    is kept nowhere; only the methods in ``allowed`` (CONNECT_METHODS, or DISCONNECT_METHODS) can be called."""

    def __init__(self, entry: dict[str, Any], user: str, password: str, timeout: float = 15,
                 allowed: frozenset[str] = CONNECT_METHODS):
        host, port = address(entry)
        self.allowed = allowed
        self.ws = _WS(host, port, entry.get("fingerprint"), timeout)
        self.n = 0
        try:
            self._login(user, password)
        except Exception:
            self.ws.close()
            raise

    def _login(self, user: str, password: str) -> None:
        try:
            got = self._call("auth.login_ex", [{"mechanism": "PASSWORD_PLAIN", "username": user, "password": password}])
            kind = str((got or {}).get("response_type") or "")
        except TrueNASError as exc:
            if "has no auth.login_ex" not in str(exc):
                raise
            kind = "SUCCESS" if self._call("auth.login", [user, password]) is True else "AUTH_ERR"
        if kind == "OTP_REQUIRED":
            raise TrueNASError(f"{user} uses two-factor sign-in, which Hisho can't do here; sign in once as an admin "
                               "without it, or make the key by hand (+ add by filling in every field)")
        if kind == "EXPIRED":
            raise TrueNASError(f"TrueNAS says {user}'s password has expired; change it in TrueNAS first")
        if kind != "SUCCESS":
            raise TrueNASError(f"TrueNAS refused the sign-in for {user}: check the user name and password")

    def call(self, method: str, *params: Any) -> Any:
        if method not in self.allowed:
            raise TrueNASError(f"{method} is not on Hisho's sign-in-once list")
        return self._call(method, list(params))


def _readonly_group(s: AdminSession) -> int | None:
    """The group that holds TrueNAS's built-in Read-only Administrator privilege (role READONLY_ADMIN alone)."""
    for p in s.call("privilege.query") or []:
        if list(p.get("roles") or []) == ["READONLY_ADMIN"]:
            for g in p.get("local_groups") or []:
                if isinstance(g, dict) and g.get("id") is not None:
                    return int(g["id"])
    return None


def _reads_with(entry: dict[str, Any], key: str) -> bool:
    """Whether a key can read what the card shows (a read-only admin can, on every 25.x we know)."""
    try:
        s = Session(entry, key)
    except TrueNASError:
        return False
    try:
        s.call("system.info")
        s.call("pool.query")
        return True
    except TrueNASError:
        return False
    finally:
        s.close()


def connect(values: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Sign in once with an admin login, then make user ``hisho-<machine>`` (no password, no SMB, in the Read-only
    Administrators group, with its own new group) and an API key ``hisho-<machine>`` for it. A name already in use
    (another Hisho's, or yours) gets a free numeric suffix: nothing that exists is reused or changed. If this
    TrueNAS has no read-only admin group, or that key can't read, the key is made for the admin user instead and
    the message says so. ``made`` in the entry lists what was made (names and ids) for Remove from TrueNAS."""
    user, password = str(values.get("user") or "").strip(), str(values.get("password") or "")
    if not user:
        raise TrueNASError("type the admin user, e.g. truenas_admin")
    entry = {"url": str(values.get("url") or "").strip()}
    host, port = address(entry)
    try:
        entry["fingerprint"] = server_fingerprint(host, port)
    except OSError as exc:
        raise TrueNASError(f"can't reach {host}:{port} ({type(exc).__name__}); check the address and that "
                           "TrueNAS is on") from None
    base = f"hisho-{_machine()}"
    s = AdminSession(entry, user, password)
    made: dict[str, Any] = {"api_keys": []}
    try:
        key_names = {str(k.get("name")) for k in s.call("api_key.query") or []}
        owner, why = user, ""
        group = _readonly_group(s)
        if group is None:
            why = "this TrueNAS has no Read-only Administrators group"
        else:
            taken = ({str(u.get("username")) for u in s.call("user.query") or []}
                     | {str(g.get("group")) for g in s.call("group.query") or []})
            me = _free(base, taken)
            try:
                got = s.call("user.create", {"username": me, "full_name": "Hisho (read only)",
                                             "group_create": True, "groups": [group], "password_disabled": True,
                                             "smb": False}) or {}
                made["user"] = {"name": me, "id": got.get("id") if isinstance(got, dict) else got, "group": me}
                owner = me
            except TrueNASError as exc:
                why = f"TrueNAS would not make user {me} ({str(exc)[:120]})"
        name = _free(base, key_names)
        got = s.call("api_key.create", {"name": name, "username": owner}) or {}
        key = got.get("key")
        made["api_keys"].append({"name": name, "id": got.get("id")})
        if owner != user and key and not _reads_with(entry, key):
            why = "the read-only key could not read pools on this TrueNAS"
            key_names.add(name)
            name, owner = _free(base, key_names), user
            got = s.call("api_key.create", {"name": name, "username": owner}) or {}
            key = got.get("key")
            made["api_keys"].append({"name": name, "id": got.get("id")})
    finally:
        s.close()
    if not key:
        raise TrueNASError("TrueNAS made the key but did not show it; try again")
    did = ([f"read-only user {made['user']['name']}"] if made.get("user") else []) + [f"API key {name}"]
    if owner != user:
        say = "Hisho can only read (pools, disks, alerts, shares)."
    else:
        say = (f"The key acts as {owner} ({why}), so it could change things; Hisho only ever calls read methods "
               "with it.")
    return {"ok": True, "entry": {**entry, "api_key": key, "made": made},
            "message": f"Made {' and '.join(did)} on {host}; nothing that was there before was changed. {say} "
                       "Your admin password was used once and not kept."}


# ── Remove from TrueNAS: delete exactly what Sign in once made ────────────

def disconnect(entry: dict[str, Any], login: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Remove from TrueNAS: sign in once with an admin login (over the certificate the entry remembers) and delete
    exactly what ``made`` lists: its API key(s), by id and name, and the user (with the group made for it) only
    when Hisho made that user. Anything already gone is said, not an error. Nothing else is touched."""
    made = entry.get("made") or {}
    if not isinstance(made, dict) or not (made.get("api_keys") or made.get("user")):
        return {"ok": False, "error": "Hisho didn't make this entry's key by signing in once, so there is nothing "
                                      "of Hisho's to remove; delete the key in TrueNAS yourself"}
    u = made.get("user") or {}
    if u and not str(u.get("name") or "").startswith("hisho-"):
        raise TrueNASError(f"{u.get('name')} is not a user Hisho makes; nothing was deleted")
    if not entry.get("fingerprint"):
        raise TrueNASError("this entry remembers no certificate, so Hisho won't send your login; press Test first")
    host, _ = address(entry)
    s = AdminSession(entry, str(login.get("user") or "").strip(), str(login.get("password") or ""),
                     allowed=DISCONNECT_METHODS)
    done, gone = [], []
    try:
        for k in made.get("api_keys") or []:
            by = [["id", "=", k["id"]]] if k.get("id") is not None else [["name", "=", str(k.get("name"))]]
            rows = [r for r in s.call("api_key.query", by) or [] if str(r.get("name")) == str(k.get("name"))]
            if rows:
                s.call("api_key.delete", rows[0]["id"])
                done.append(f"API key {k.get('name')}")
            else:
                gone.append(f"API key {k.get('name')}")
        if u:
            rows = [r for r in s.call("user.query", [["username", "=", u["name"]]]) or []
                    if u.get("id") is None or r.get("id") == u.get("id")]
            if rows:
                s.call("user.delete", rows[0]["id"], {"delete_group": True})
                done.append(f"user {u['name']}")
            else:
                gone.append(f"user {u['name']}")
    finally:
        s.close()
    said = "; ".join(x for x in ["deleted " + ", ".join(done) if done else "",
                                 "already gone: " + ", ".join(gone) if gone else ""] if x)
    return {"ok": True, "message": f"On {host}: {said}. Nothing else was touched. Your admin password was used once "
                                   "and not kept."}


def address(entry: dict[str, Any]) -> tuple[str, int]:
    text = str(entry.get("url") or "").strip().rstrip("/")
    if not text:
        raise TrueNASError("no address: give TrueNAS's IP or name")
    if text.startswith("http://"):
        raise TrueNASError("Hisho only talks to TrueNAS over https (the API key would travel in clear)")
    text = text.split("://", 1)[-1].split("/", 1)[0]
    host, _, port = text.partition(":")
    return host, int(port or 443)


# ── reading, cut down to what the card shows ──────────────────────────────

def _date(v: Any) -> float | None:
    if isinstance(v, dict) and "$date" in v:
        return float(v["$date"]) / 1000
    return float(v) if isinstance(v, (int, float)) else None


def _members(topology: Any) -> list[dict[str, Any]]:
    """Every disk in a pool (pool.query's topology), with ZFS's read / write / checksum error counts
    and the vdev it sits in, so an error can be pinned to one disk."""
    out: list[dict[str, Any]] = []

    def walk(node: dict[str, Any], vdev: str) -> None:
        kids = node.get("children") or []
        if kids:
            for kid in kids:
                walk(kid, node.get("name") or vdev)
            return
        stats = node.get("stats") or {}
        out.append({"disk": node.get("disk") or str(node.get("device") or node.get("path") or "?").split("/")[-1],
                    "status": node.get("status"), "vdev": vdev,
                    "read": int(stats.get("read_errors") or 0), "write": int(stats.get("write_errors") or 0),
                    "checksum": int(stats.get("checksum_errors") or 0)})
    for section, nodes in (topology or {}).items():
        for node in nodes or []:
            walk(node, section if not (node.get("children")) else node.get("name") or section)
    return out


def _errors_text(m: dict[str, Any]) -> str:
    parts = [f"{m[k]} {k}" for k in ("checksum", "read", "write") if m[k]]
    return ", ".join(parts) if parts else "no errors"


def read(entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    s = Session(entry, ctx.secret(entry["api_key"]).strip())
    try:
        info = s.call("system.info") or {}
        pools = s.call("pool.query") or []
        disks = s.call("disk.query") or []
        try:
            temps = s.call("disk.temperatures", [d["name"] for d in disks if d.get("name")]) or {}
        except TrueNASError:
            temps = {}
        alerts = s.call("alert.list") or []
        shares = s.call("sharing.smb.query") or []
        services = s.call("service.query", [["service", "in", ["cifs", "nfs"]]]) or []
    finally:
        s.close()
    return {
        "version": info.get("version"), "hostname": info.get("hostname"), "uptime": info.get("uptime_seconds"),
        "pools": [{"name": p.get("name"), "status": p.get("status"), "healthy": p.get("healthy"),
                   "size": p.get("size"), "allocated": p.get("allocated"), "free": p.get("free"),
                   "scan": {k: (p.get("scan") or {}).get(k)
                            for k in ("function", "state", "percentage", "end_time", "errors", "total_secs_left")},
                   "members": _members(p.get("topology"))}
                  for p in pools],
        "disks": [{"name": d.get("name"), "model": d.get("model"), "serial": d.get("serial"), "size": d.get("size"),
                   "pool": d.get("pool"), "temp": temps.get(d.get("name")) if isinstance(temps, dict) else None}
                  for d in disks],
        "alerts": [{"level": a.get("level"), "text": a.get("formatted") or a.get("klass"), "klass": a.get("klass")}
                   for a in alerts if not a.get("dismissed")],
        "shares": [{"name": x.get("name"), "path": x.get("path"), "enabled": x.get("enabled")} for x in shares],
        "services": {x.get("service"): x.get("state") for x in services},
    }


def _tb(n: Any) -> str:
    """Binary units, as TrueNAS's own pages show them."""
    n = float(n or 0)
    return f"{n / 2 ** 40:.1f} TiB" if n >= 2 ** 40 else f"{n / 2 ** 30:.0f} GiB"


def _scrub(scan: dict[str, Any]) -> str:
    what = str(scan.get("function") or "scrub").lower()
    if scan.get("state") == "SCANNING":
        left = scan.get("total_secs_left")  # ZFS's own estimate at the current speed
        eta = ""
        if isinstance(left, (int, float)) and left > 0:
            eta = f", about {left / 3600:.1f} h left" if left >= 3600 else f", about {max(1, round(left / 60))} min left"
        return f"{what} running, {float(scan.get('percentage') or 0):.0f}% done{eta}"
    return f"last {what} {_ago(_date(scan.get('end_time')))}"


def _ago(ts: float | None) -> str:
    if not ts:
        return "never"
    days = (time.time() - ts) / 86400
    return "today" if days < 1 else f"{days:.0f} days ago"


def findings(name: str, entry: dict[str, Any], d: dict[str, Any]) -> list[dict[str, Any]]:
    """What's wrong, in words. Titles carry no numbers, so each stays one alert."""
    out: list[dict[str, Any]] = []

    def add(title: str, detail: str, severity: str = "warn", **extra: Any) -> None:
        out.append({"entry": name, "severity": severity, "title": title, "detail": detail, **extra})

    serials = {x["name"]: x for x in d["disks"]}
    for p in d["pools"]:
        bad = [m for m in p.get("members") or [] if m["read"] or m["write"] or m["checksum"]]
        where = ("; the errors are on " + ", ".join(f"{m['disk']} ({_errors_text(m)})" for m in bad) + ".") if bad else ""
        for m in bad:
            disk = serials.get(m["disk"]) or {}
            # The counts are in the title (what he reads first); the key is the disk, so a growing count
            # updates one alert instead of making a new one each check.
            add(f"{p['name']}: {_errors_text(m)} errors on {m['disk']}",
                f"ZFS counts {m['read']} read, {m['write']} write and {m['checksum']} checksum errors on {m['disk']}"
                f"{' (serial ' + str(disk.get('serial')) + ', ' + str(disk.get('model') or '?') + ')' if disk.get('serial') else ''}"
                f" in {m['vdev']} of pool {p['name']}, status {m['status']}. Errors on one disk point at that disk, "
                "its cable or its slot. TrueNAS > Storage > " + p["name"] + " > View VDEVs.",
                "critical", key=f"pool {p['name']} disk errors:{disk.get('serial') or m['disk']}")
        if p["status"] != "ONLINE":
            add(f"pool {p['name']} is {str(p['status']).lower()}",
                f"Pool {p['name']} reports {p['status']}. Open TrueNAS > Storage to see which disk; data is at risk "
                "until it is ONLINE again.", "critical")
        elif p["healthy"] is False:
            add(f"pool {p['name']} is unhealthy",
                f"Pool {p['name']} is online but ZFS reports errors on it{where or '.'} TrueNAS > Storage > {p['name']} > "
                "View VDEVs shows the disks; a scrub lists any damaged files.", "critical")
        if p["size"] and p["allocated"] and p["allocated"] / p["size"] >= POOL_FULL:
            add(f"pool {p['name']} is nearly full",
                f"{100 * p['allocated'] / p['size']:.0f}% used ({_tb(p['free'])} free). ZFS slows down past ~85%.")
        scan = p["scan"] or {}
        if scan.get("errors"):
            add(f"pool {p['name']} has scrub errors",
                f"Its {_scrub(scan)}; it found {scan['errors']} error(s){where or '.'}", "critical")
        ended = _date(scan.get("end_time"))
        if (p["status"] == "ONLINE" and scan.get("state") != "SCANNING"
                and (not ended or time.time() - ended > SCRUB_DAYS * 86400 * 1.5)):
            add(f"pool {p['name']} hasn't been scrubbed lately",
                f"Last scrub {_ago(ended)}. A scrub reads every block and finds silent errors; TrueNAS > Data "
                "Protection > Scrub Tasks.")
    hot = [x for x in d["disks"] if isinstance(x["temp"], (int, float)) and x["temp"] >= int(entry.get("disk_warn_c") or DISK_WARN_C)]
    if hot:
        add("disks are running hot",
            ", ".join(f"{x['name']} {x['temp']:.0f} C" for x in sorted(hot, key=lambda x: -x["temp"])[:8])
            + f" (alert at {entry.get('disk_warn_c') or DISK_WARN_C} C; most drives are rated to 60 C). Improve airflow.")
    crit = [a for a in d["alerts"] if str(a["level"]).upper() in ("CRITICAL", "ERROR", "ALERT", "EMERGENCY")]
    for a in crit[:8]:
        # One TrueNAS class fires once per disk (DiskTemperatureTooHot for sdd, sde...): each instance is its own
        # alert, keyed by the disk's serial (stable across /dev renames), else its device. The text holds the live
        # temperature, so it can't be the key. "was" is the old shared key, so acks and push state carry over.
        dev, serial = _instance(str(a["text"]))
        klass = f"TrueNAS alert {a['klass']}"
        if dev or serial:
            add(f"{klass} ({dev or serial})", str(a["text"])[:300], "critical", key=f"{klass}:{serial or dev}", was=klass)
        else:
            add(klass, str(a["text"])[:300], "critical")
    watch = [s.strip() for s in str(entry.get("watch_shares") or "").split(",") if s.strip()]
    smb_up = d["services"].get("cifs") == "RUNNING"
    for share in watch:
        found = next((x for x in d["shares"] if str(x["name"]).lower() == share.lower()), None)  # SMB names ignore case
        if not found or not found["enabled"] or not smb_up:
            why = "isn't there" if not found else "is disabled" if not found["enabled"] else "is down (SMB service stopped)"
            add(f"share {share} is not available", f"The SMB share {share} {why}. Things that back up to it will fail.",
                "critical")
    return out


_DEV = re.compile(r"/dev/((?:sd[a-z]+|nvme\d+n\d+|da\d+|ada\d+))\b")
_SERIAL = re.compile(r"serial:?\s*([A-Za-z0-9_-]{4,})")


def _instance(text: str) -> tuple[str | None, str | None]:
    """(device, serial) a TrueNAS alert is about, when its text names them."""
    dev, serial = _DEV.search(text), _SERIAL.search(text)
    return (dev.group(1) if dev else None), (serial.group(1) if serial else None)


def summary(entries: dict[str, dict[str, Any]], ctx: Any) -> dict[str, Any]:
    problems, pools, down = [], 0, 0
    for name, entry in entries.items():
        try:
            d = read(entry, ctx)
        except Exception as exc:  # noqa: BLE001
            down += 1
            problems.append({"entry": name, "severity": "warn", "title": f"{name} does not answer",
                             "detail": f"Hisho can't read TrueNAS {name}: {str(exc)[:200] or type(exc).__name__}"})
            continue
        pools += len(d["pools"])
        problems += findings(name, entry, d)
    n = len(entries)
    return {"state": "down" if any(p["severity"] == "critical" for p in problems) or (n and down == n)
            else "warn" if problems else "ok",
            "headline": f"{n} TrueNAS · {pools} pool{'s' * (pools != 1)}" + (f" · {down} not answering" if down else ""),
            "problems": problems}


def _member_facts(p: dict[str, Any], disks: list[dict[str, Any]]) -> list[str]:
    """Per-disk ZFS errors for addon_details (what Investigate and Ask read): every disk with errors,
    with its serial, else one line saying none have any."""
    members = p.get("members") or []
    if not members:
        return []
    serial = {x["name"]: x.get("serial") for x in disks}
    bad = [m for m in members if m["read"] or m["write"] or m["checksum"]]
    if not bad:
        return [f"disks: {len(members)}, none with read, write or checksum errors"]
    return [f"errors on {m['disk']} (serial {serial.get(m['disk']) or '?'}, {m['vdev']}, {m['status']}): "
            f"{m['read']} read, {m['write']} write, {m['checksum']} checksum" for m in bad] \
        + [f"other {len(members) - len(bad)} disks: no errors"]


def details(entries: dict[str, dict[str, Any]], ctx: Any) -> list[dict[str, Any]]:
    sections = []
    for name, entry in entries.items():
        try:
            d = read(entry, ctx)
        except Exception as exc:  # noqa: BLE001
            sections.append({"title": name, "entry": name, "state": "down",
                             "facts": [f"not working: {str(exc)[:200] or type(exc).__name__}"], "items": []})
            continue
        found = findings(name, entry, d)
        items = []
        for p in d["pools"]:
            scan = p["scan"] or {}
            items.append({"id": f"pool-{p['name']}", "name": f"Pool {p['name']}",
                          "state": "up" if p["status"] == "ONLINE" and p["healthy"] is not False else "warn",
                          "facts": [str(p["status"]), f"{_tb(p['allocated'])} used of {_tb(p['size'])} ({_tb(p['free'])} free)",
                                    _scrub(scan) + (f", {scan['errors']} errors" if scan.get("errors") else "")]
                                   + _member_facts(p, d["disks"]),
                          "actions": []})
        temps = sorted((x for x in d["disks"] if isinstance(x["temp"], (int, float))), key=lambda x: -x["temp"])
        if d["disks"]:
            items.append({"id": "disks", "name": f"Disks ({len(d['disks'])})",
                          "state": "warn" if any(f["title"].endswith("disks are running hot") for f in found) else "up",
                          "facts": ([f"hottest: " + ", ".join(f"{x['name']} {x['temp']:.0f} C" for x in temps[:6])]
                                    if temps else ["temperatures not reported"])
                                   + [f"{x['name']}: {x['model'] or '?'} {_tb(x['size'])}"
                                      + (f" (pool {x['pool']})" if x.get("pool") else "") for x in d["disks"][:24]],
                          "actions": []})
        smb = d["services"].get("cifs")
        items.append({"id": "shares", "name": f"SMB shares ({len(d['shares'])})",
                      "state": "up" if smb == "RUNNING" else "warn",
                      "facts": [f"SMB service {str(smb or 'unknown').lower()}"]
                               + [f"{x['name']} -> {x['path']}" + ("" if x["enabled"] else " (disabled)") for x in d["shares"]],
                      "actions": []})
        if d["alerts"]:
            items.append({"id": "alerts", "name": f"TrueNAS alerts ({len(d['alerts'])})", "state": "warn",
                          "facts": [f"{a['level']}: {str(a['text'])[:200]}" for a in d["alerts"][:10]], "actions": []})
        sections.append({"title": name, "entry": name,
                         "state": "down" if any(f["severity"] == "critical" for f in found) else "warn" if found else "ok",
                         "facts": [f"TrueNAS {d['version']} on {d['hostname']}", f"up {int(d['uptime'] or 0) // 86400} d"]
                                  + [f["title"] for f in found]
                                  + ([entry["note"]] if entry.get("note") else []),
                         "items": items})
    return sections


def test(entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    fill: dict[str, Any] = {}
    try:
        host, port = address(entry)
        if not entry.get("fingerprint"):
            try:
                fill["fingerprint"] = server_fingerprint(host, port)
            except OSError as exc:
                return {"ok": False, "error": f"can't reach {host}:{port}: {exc}"}
        d = read({**entry, **fill}, ctx)
    except TrueNASError as exc:
        return {"ok": False, "error": str(exc), "fill": fill}
    return {"ok": True, "fill": fill,
            "message": f"Connected to TrueNAS {d['version']} ({d['hostname']}): {len(d['pools'])} pool(s), "
                       f"{len(d['disks'])} disks, {len(d['shares'])} SMB shares"
                       + (" · certificate fingerprint filled in" if fill else "")}


def describe_secret(entry: dict[str, Any], ctx: Any) -> str:
    """The 'What:' line of the key's Infisical comment."""
    d = read(entry, ctx)
    s = Session(entry, ctx.secret(entry["api_key"]).strip())
    try:
        me = s.call("auth.me") or {}
        user = me.get("pw_name") or "?"
        roles = (me.get("privilege") or {}).get("roles") or []
        roles = roles.get("$set", []) if isinstance(roles, dict) else roles
        names = [k.get("name") for k in s.call("api_key.query") or [] if k.get("username") == user]
    finally:
        s.close()
    level = "FULL ADMIN" if "FULL_ADMIN" in roles else "read-only admin" if "READONLY_ADMIN" in roles else "limited"
    named = f' "{names[0]}"' if len(names) == 1 else (f" (one of {', '.join(map(str, names))})" if names else "")
    return (f"TrueNAS {d['version']} ({d['hostname']}, {address(entry)[0]}) API key{named} of user {user}, {level}. "
            "Hisho only calls read methods with it (pools, disks, alerts, shares).")
