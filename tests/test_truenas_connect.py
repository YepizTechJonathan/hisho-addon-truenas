"""TrueNAS add-on: Found on your network and Sign in once (an admin login used once to make a read-only user
and its API key). No real TrueNAS: the websocket is a fake that answers JSON-RPC."""
from __future__ import annotations

import json
import time

import pytest

from hisho import addons
from hisho import connect as hconnect

RO_PRIVILEGE = {"id": 2, "name": "Read-only Administrator", "roles": ["READONLY_ADMIN"],
                "local_groups": [{"id": 41, "gid": 951, "name": "builtin_readonly_administrators"}]}
FULL_PRIVILEGE = {"id": 1, "name": "Local Administrator", "roles": ["FULL_ADMIN"], "local_groups": [{"id": 40, "gid": 950}]}


class FakeTrueNAS:
    """One TrueNAS, answering every websocket opened to it (admin sign-in and the new key's check)."""

    def __init__(self, password="right-pass", users=(), keys=(), privileges=(FULL_PRIVILEGE, RO_PRIVILEGE),
                 login_ex=True, ro_reads=True, otp=False):
        self.password, self.users, self.keys, self.privileges = password, list(users), list(keys), list(privileges)
        self.login_ex, self.ro_reads, self.otp = login_ex, ro_reads, otp
        self.calls, self.opened = [], []

    def ws(self, host, port, fingerprint, timeout=15):
        self.opened.append((host, port, fingerprint))
        return _Conn(self)

    def answer(self, conn, method, params):
        self.calls.append((method, params))
        if method == "auth.login_ex":
            if not self.login_ex:
                return {"error": {"code": -32601, "message": "Method not found"}}
            p = params[0]
            kind = "OTP_REQUIRED" if self.otp else "SUCCESS" if p["password"] == self.password else "AUTH_ERR"
            conn.who = p["username"] if kind == "SUCCESS" else None
            return {"result": {"response_type": kind}}
        if method == "auth.login":
            conn.who = params[0] if params[1] == self.password else None
            return {"result": conn.who is not None}
        if method == "auth.login_with_api_key":
            conn.who = next((k["username"] for k in self.keys if k["key"] == params[0]), None)
            return {"result": conn.who is not None}
        assert conn.who, "called before signing in"
        if conn.who == "hisho" and not self.ro_reads:
            return {"error": {"code": 13, "message": "Not authorized", "data": {"reason": "Not authorized"}}}
        if method == "privilege.query":
            return {"result": self.privileges}
        if method == "user.query":
            return {"result": [u for u in self.users if u["username"] == params[0][0][2]]}
        if method == "user.create":
            self.users.append(params[0])
            return {"result": {"id": 77, **params[0]}}
        if method == "api_key.query":
            return {"result": [{"name": k["name"], "username": k["username"]} for k in self.keys]}
        if method == "api_key.create":
            key = f"{len(self.keys) + 1}-made-key-for-{params[0]['username']}"
            self.keys.append({**params[0], "key": key})
            return {"result": {"id": len(self.keys), **params[0], "key": key}}
        if method == "system.info":
            return {"result": {"version": "25.10.7", "hostname": "truenas"}}
        if method in ("pool.query", "disk.query", "alert.list", "sharing.smb.query", "service.query"):
            return {"result": []}
        if method == "disk.temperatures":
            return {"result": {}}
        raise AssertionError(f"unexpected {method}")


class _Conn:
    def __init__(self, nas):
        self.nas, self.who, self.out = nas, None, []

    def send_text(self, text):
        req = json.loads(text)
        self.out.append({"jsonrpc": "2.0", "id": req["id"], **self.nas.answer(self, req["method"], req["params"])})

    def recv_text(self):
        return json.dumps(self.out.pop(0))

    def close(self):
        pass


@pytest.fixture
def nas(monkeypatch, addon):
    mod = addons.provider(addon)
    fake = FakeTrueNAS()
    monkeypatch.setattr(mod, "_WS", fake.ws)
    monkeypatch.setattr(mod, "server_fingerprint", lambda host, port=443: "AB:CD")
    return mod, fake


def test_found_on_your_network_looks_for_truenas_api_versions(addon):
    """TrueNAS's sign-in page names nothing (its title is set by script): its API version list does."""
    import re
    probes = addon.manifest["discover"]
    assert [p["http"] for p in probes] == ["https://{ip}/api/versions"]
    assert re.search(probes[0]["match"], '["v25.04.0", "v25.10.5"]') and not re.search(probes[0]["match"], "<html>")
    tcp = lambda ip, port, banner="": ip == "192.0.2.21" and port == 443
    http = lambda url, match: url == "https://192.0.2.21/api/versions"
    got = hconnect.scan(addon, ["192.0.2.16/28"], tcp=tcp, http=http, rmcp=lambda *a: False, workers=2)
    assert got == [{"ip": "192.0.2.21", "title": "TrueNAS at 192.0.2.21", "fill": {"url": "192.0.2.21"}}]
    assert addon.manifest["connect"]["form"] == ["url"] and set(addon.manifest["connect"]["fields"]) == {"user", "password"}


def test_sign_in_once_makes_a_read_only_user_and_its_key(nas):
    mod, fake = nas
    out = mod.connect({"url": "192.0.2.21", "user": "truenas_admin", "password": "right-pass"}, None)
    assert out["ok"] and out["entry"] == {"url": "192.0.2.21", "fingerprint": "AB:CD", "api_key": "1-made-key-for-hisho"}
    assert all(o == ("192.0.2.21", 443, "AB:CD") for o in fake.opened)       # every connection pinned
    assert fake.calls[0] == ("auth.login_ex", [{"mechanism": "PASSWORD_PLAIN", "username": "truenas_admin",
                                                "password": "right-pass"}])
    [created] = [p[0] for m, p in fake.calls if m == "user.create"]
    assert created == {"username": "hisho", "full_name": "Hisho (read only)", "group_create": True, "groups": [41],
                       "password_disabled": True, "smb": False}
    assert ("api_key.create", [{"name": "hisho", "username": "hisho"}]) in fake.calls
    assert "can only read" in out["message"] and "right-pass" not in json.dumps(out)


def test_an_existing_user_and_key_name_are_reused_or_renamed(nas):
    mod, fake = nas
    fake.users = [{"username": "hisho"}]
    fake.keys = [{"name": "hisho", "username": "hisho", "key": "old"}]
    fake.login_ex = False                                     # an older 25.x: auth.login
    out = mod.connect({"url": "192.0.2.21", "user": "truenas_admin", "password": "right-pass"}, None)
    assert not any(m == "user.create" for m, _ in fake.calls)
    assert ("auth.login", ["truenas_admin", "right-pass"]) in fake.calls
    assert ("api_key.create", [{"name": f"hisho-{time.strftime('%Y%m%d')}", "username": "hisho"}]) in fake.calls
    assert out["entry"]["api_key"].endswith("for-hisho")


def test_without_a_read_only_group_the_key_is_the_admins_and_it_says_so(nas):
    mod, fake = nas
    fake.privileges = [FULL_PRIVILEGE]
    out = mod.connect({"url": "192.0.2.21", "user": "truenas_admin", "password": "right-pass"}, None)
    assert out["entry"]["api_key"].endswith("for-truenas_admin")
    assert "acts as truenas_admin" in out["message"] and "no Read-only Administrators group" in out["message"]


def test_a_read_only_key_that_cannot_read_falls_back_to_the_admin(nas):
    mod, fake = nas
    fake.ro_reads = False
    out = mod.connect({"url": "192.0.2.21", "user": "truenas_admin", "password": "right-pass"}, None)
    made = [p[0] for m, p in fake.calls if m == "api_key.create"]
    assert [k["username"] for k in made] == ["hisho", "truenas_admin"] and made[1]["name"] != made[0]["name"]
    assert out["entry"]["api_key"].endswith("for-truenas_admin") and "could not read" in out["message"]


def test_a_wrong_password_or_two_factor_is_said_plainly(nas):
    mod, fake = nas
    with pytest.raises(mod.TrueNASError) as e:
        mod.connect({"url": "192.0.2.21", "user": "truenas_admin", "password": "wrong-pass"}, None)
    assert "refused the sign-in for truenas_admin" in str(e.value) and "wrong-pass" not in str(e.value)
    assert [m for m, _ in fake.calls] == ["auth.login_ex"]                 # nothing made
    fake.otp = True
    with pytest.raises(mod.TrueNASError, match="two-factor"):
        mod.connect({"url": "192.0.2.21", "user": "truenas_admin", "password": "right-pass"}, None)


def test_sign_in_once_refuses_plain_http(nas):
    mod, fake = nas
    with pytest.raises(mod.TrueNASError, match="only talks to TrueNAS over https"):
        mod.connect({"url": "http://192.0.2.21", "user": "truenas_admin", "password": "right-pass"}, None)
    assert fake.calls == []


def test_sign_in_once_through_core_tests_and_saves_the_key(fleet, nas, monkeypatch, tmp_path):
    monkeypatch.setattr(addons, "LOCAL_SECRETS", str(tmp_path / "secrets.env"))
    mod, fake = nas
    tn = addons.get("truenas")
    out = hconnect.connect(tn, "nas", {"url": "192.0.2.21", "user": "truenas_admin", "password": "right-pass"})
    assert out["ok"], out
    e = addons.read_config("truenas")["entries"]["nas"]
    assert e["fingerprint"] == "AB:CD" and "password" not in e and "user" not in e
    saved = open(addons.config_path("truenas")).read()
    assert "made-key" not in saved and "right-pass" not in saved
