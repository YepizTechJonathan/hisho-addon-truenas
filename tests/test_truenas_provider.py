"""TrueNAS add-on: JSON-RPC over a stdlib websocket, read-only allow-list, findings in words."""
from __future__ import annotations

import json
import socket
import struct
import time
from importlib import util
from pathlib import Path

import pytest

from hisho import addons

spec = util.spec_from_file_location("truenas_provider", Path(__file__).resolve().parents[1] / "provider.py")
tn = util.module_from_spec(spec)
spec.loader.exec_module(tn)

NOW = time.time()


def _data(**over):
    d = {"version": "25.10.7", "hostname": "truenas", "uptime": 86400 * 3,
         "pools": [{"name": "tank", "status": "ONLINE", "healthy": True, "size": 60e12, "allocated": 1.5e12,
                    "free": 58.5e12, "scan": {"function": "SCRUB", "state": "FINISHED",
                                              "end_time": {"$date": (NOW - 5 * 86400) * 1000}, "errors": 0}}],
         "disks": [{"name": "sda", "model": "WDC", "serial": "x", "size": 8e12, "pool": "tank", "temp": 41},
                   {"name": "sdb", "model": "WDC", "serial": "y", "size": 8e12, "pool": "tank", "temp": 44}],
         "alerts": [], "shares": [{"name": "proxmoxbackup", "path": "/mnt/tank/pb", "enabled": True}],
         "services": {"cifs": "RUNNING", "nfs": "STOPPED"}}
    d.update(over)
    return d


ENTRY = {"url": "192.0.2.21", "api_key": "TRUENAS_CE_API_KEY", "watch_shares": "ProxmoxBackup"}  # TrueNAS names it proxmoxbackup


def test_a_healthy_truenas_has_no_findings():
    assert tn.findings("truenas", ENTRY, _data()) == []


def test_findings_say_what_is_wrong_without_numbers_in_titles():
    d = _data()
    d["pools"][0].update(status="DEGRADED", healthy=False, allocated=55e12, free=5e12)
    d["pools"][0]["scan"]["errors"] = 3
    d["disks"][1]["temp"] = 58
    d["alerts"] = [{"level": "CRITICAL", "text": "Device /dev/sdb is causing slow I/O", "klass": "SMART"}]
    d["services"]["cifs"] = "STOPPED"
    found = {f["title"]: f for f in tn.findings("truenas", ENTRY, d)}
    assert found["pool tank is degraded"]["severity"] == "critical"
    assert found["pool tank has scrub errors"]["severity"] == "critical"
    assert "92% used" in found["pool tank is nearly full"]["detail"]
    assert "sdb 58 C" in found["disks are running hot"]["detail"]
    assert found["TrueNAS alert SMART (sdb)"]["severity"] == "critical"
    assert "SMB service stopped" in found["share ProxmoxBackup is not available"]["detail"]
    assert not any(ch.isdigit() for t in found for ch in t)


def test_an_old_scrub_is_flagged():
    d = _data()
    d["pools"][0]["scan"]["end_time"] = {"$date": (NOW - 90 * 86400) * 1000}
    [f] = tn.findings("truenas", ENTRY, d)
    assert f["title"] == "pool tank hasn't been scrubbed lately" and "90 days ago" in f["detail"]


def test_details_and_summary(monkeypatch):
    monkeypatch.setattr(tn, "read", lambda entry, ctx: _data())
    [sec] = tn.details({"truenas": ENTRY}, None)
    assert sec["state"] == "ok" and sec["facts"][0] == "TrueNAS 25.10.7 on truenas"
    pool, disks, shares = sec["items"]
    assert "1.4 TiB used of 54.6 TiB (53.2 TiB free)" in pool["facts"] and "last scrub 5 days ago" in pool["facts"]
    assert disks["facts"][0] == "hottest: sdb 44 C, sda 41 C"
    assert "proxmoxbackup -> /mnt/tank/pb" in shares["facts"]
    assert tn.summary({"truenas": ENTRY}, None)["headline"] == "1 TrueNAS · 1 pool"


def test_http_and_bad_addresses_are_refused():
    with pytest.raises(tn.TrueNASError, match="https"):
        tn.address({"url": "http://192.0.2.21"})
    assert tn.address({"url": "https://nas.local:8443/ui"}) == ("nas.local", 8443)


class FakeWS:
    def __init__(self, answers):
        self.sent, self.answers = [], answers

    def send_text(self, text):
        self.sent.append(json.loads(text))

    def recv_text(self):
        req = self.sent[-1]
        if req["method"] == "auth.login_with_api_key":
            return json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": self.answers.get("login", True)})
        # an unrelated event first, then the answer
        self.answers.setdefault("_events", 0)
        if self.answers["_events"] == 0:
            self.answers["_events"] = 1
            return json.dumps({"jsonrpc": "2.0", "method": "collection_update", "params": {}})
        self.answers["_events"] = 0
        return json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": self.answers.get(req["method"])})

    def close(self):
        pass


def _session(monkeypatch, answers):
    ws = FakeWS(answers)
    monkeypatch.setattr(tn, "_WS", lambda *a, **k: ws)
    return tn.Session(ENTRY, "key-123"), ws


def test_session_logs_in_skips_events_and_only_reads(monkeypatch):
    s, ws = _session(monkeypatch, {"system.info": {"version": "25.10.7"}})
    assert ws.sent[0] == {"jsonrpc": "2.0", "id": 1, "method": "auth.login_with_api_key", "params": ["key-123"]}
    assert s.call("system.info") == {"version": "25.10.7"}
    with pytest.raises(tn.TrueNASError, match="read-only list"):
        s.call("pool.scrub.run", "tank")
    with pytest.raises(tn.TrueNASError, match="read-only list"):
        s.call("system.shutdown")


def test_a_refused_key_is_said_plainly(monkeypatch):
    with pytest.raises(tn.TrueNASError, match="refused the API key"):
        _session(monkeypatch, {"login": False})


def test_websocket_frames_round_trip():
    a, b = socket.socketpair()
    ws = tn._WS.__new__(tn._WS)
    ws.sock, ws.buf = a, b""
    ws.send_text("hello")
    raw = b.recv(100)
    assert raw[0] == 0x81 and raw[1] & 0x80  # FIN+text, client frames are masked
    mask, body = raw[2:6], raw[6:]
    assert bytes(x ^ mask[i % 4] for i, x in enumerate(body)) == b"hello"
    big = json.dumps({"x": "y" * 70000}).encode()
    b.sendall(b"\x89\x00" + b"\x01" + bytes([126]) + struct.pack("!H", 3) + b"abc" + b"\x80" + bytes([127])
              + struct.pack("!Q", len(big) - 3) + big[3:])  # ping, then a 2-frame message (64-bit length)
    assert ws.recv_text() == "abc" + big[3:].decode()
    assert b.recv(10)[:1] == b"\x8a"  # it answered the ping with a pong


def test_a_running_scrub_on_an_unhealthy_online_pool():
    d = _data()
    d["pools"][0].update(healthy=False)
    d["pools"][0]["scan"] = {"function": "SCRUB", "state": "SCANNING", "percentage": 41.4, "end_time": None, "errors": 2}
    found = {f["title"]: f for f in tn.findings("truenas", ENTRY, d)}
    assert set(found) == {"pool tank is unhealthy", "pool tank has scrub errors"}
    assert "scrub running, 41% done" in found["pool tank has scrub errors"]["detail"]


HOT = ("Disk /dev/{dev} (with serial: {serial}) critical temperature threshold is 60 degrees celsius and the "
       "current temp is {t} degrees celsius")


def test_each_disk_of_a_repeated_truenas_alert_is_its_own_alert_keyed_by_serial():
    d = _data()
    d["alerts"] = [{"level": "CRITICAL", "klass": "DiskTemperatureTooHot", "text": HOT.format(dev=dev, serial=sn, t=t)}
                   for dev, sn, t in (("sdk", "ZL2L1EJL", 60), ("sdj", "ZL2EMSHX", 61))]
    d["alerts"].append({"level": "CRITICAL", "klass": "ScrubPaused", "text": "Scrub of pool tank is paused"})
    found = [f for f in tn.findings("truenas", ENTRY, d) if f["title"].startswith("TrueNAS alert")]
    assert [f["title"] for f in found] == ["TrueNAS alert DiskTemperatureTooHot (sdk)",
                                           "TrueNAS alert DiskTemperatureTooHot (sdj)", "TrueNAS alert ScrubPaused"]
    assert found[0]["key"] == "TrueNAS alert DiskTemperatureTooHot:ZL2L1EJL"
    assert found[0]["was"] == "TrueNAS alert DiskTemperatureTooHot" and "key" not in found[2]
    # the temperature moves, the key doesn't
    d["alerts"][0]["text"] = HOT.format(dev="sdk", serial="ZL2L1EJL", t=64)
    assert tn.findings("truenas", ENTRY, d)[-3]["key"] == found[0]["key"]


def test_addon_items_take_the_problems_own_key_and_old_key(monkeypatch):
    from types import SimpleNamespace
    fake = SimpleNamespace(name="truenas", title="TrueNAS")
    monkeypatch.setattr(addons, "active", lambda *a: [(fake, "kihon")])
    monkeypatch.setattr(addons, "problems", lambda a: [])
    monkeypatch.setitem(addons._summaries, "truenas", {"problems": [
        {"entry": "truenas", "title": "TrueNAS alert X (sdk)", "key": "TrueNAS alert X:SN1", "was": "TrueNAS alert X"},
        {"entry": "truenas", "title": "pool tank is degraded"}]})
    a, b = addons.attention("/tmp")
    assert a["key"] == "addon:truenas:truenas:TrueNAS alert X:SN1" and a["was"] == "addon:truenas:truenas:TrueNAS alert X"
    assert b["key"] == "addon:truenas:truenas:pool tank is degraded" and "was" not in b


TOPOLOGY = {"data": [{"name": "raidz2-0", "type": "RAIDZ2", "children": [
    {"type": "DISK", "disk": "sda", "status": "ONLINE", "stats": {"read_errors": 0, "write_errors": 0, "checksum_errors": 0}},
    {"type": "DISK", "disk": "sdh", "status": "ONLINE", "stats": {"read_errors": 0, "write_errors": 0, "checksum_errors": 84}}]}],
    "cache": [], "log": [], "spare": []}


def test_errors_are_pinned_to_the_disk_they_are_on():
    members = tn._members(TOPOLOGY)
    assert [(m["disk"], m["vdev"], m["checksum"]) for m in members] == [("sda", "raidz2-0", 0), ("sdh", "raidz2-0", 84)]
    d = _data()
    d["disks"].append({"name": "sdh", "model": "ST16000", "serial": "ZL2SDH01", "size": 16e12, "pool": "tank", "temp": 40})
    d["pools"][0].update(healthy=False, members=members)
    d["pools"][0]["scan"]["errors"] = 84
    found = {f["title"]: f for f in tn.findings("truenas", ENTRY, d)}
    disk = found["tank: 84 checksum errors on sdh"]
    assert disk["severity"] == "critical" and disk["key"] == "pool tank disk errors:ZL2SDH01"   # stable as it grows
    assert "ZL2SDH01" in disk["detail"] and "raidz2-0" in disk["detail"]
    assert "the errors are on sdh (84 checksum)" in found["pool tank is unhealthy"]["detail"]
    assert "sdh (84 checksum)" in found["pool tank has scrub errors"]["detail"]
    # what Investigate and Ask read through addon_details
    facts = tn._member_facts(d["pools"][0], d["disks"])
    assert facts[0] == "errors on sdh (serial ZL2SDH01, raidz2-0, ONLINE): 0 read, 0 write, 84 checksum"
    assert facts[1] == "other 1 disks: no errors"


def test_a_clean_pool_says_so():
    p = {"members": tn._members({"data": [{"name": "mirror-0", "children": [
        {"disk": "sda", "status": "ONLINE", "stats": {}}, {"disk": "sdb", "status": "ONLINE", "stats": {}}]}]})}
    assert tn._member_facts(p, []) == ["disks: 2, none with read, write or checksum errors"]
