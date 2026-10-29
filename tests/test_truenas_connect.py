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

    def __init__(self, password="right-pass", users=(), keys=(), groups=(), privileges=(FULL_PRIVILEGE, RO_PRIVILEGE),
                 login_ex=True, ro_reads=True, otp=False):
        self.password, self.users, self.keys, self.privileges = password, list(users), list(keys), list(privileges)
        self.groups = list(groups) or [{"id": 40, "group": "builtin_administrators"}]
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
        if conn.who.startswith("hisho-") and not self.ro_reads:
            return {"error": {"code": 13, "message": "Not authorized", "data": {"reason": "Not authorized"}}}
        if method == "privilege.query":
            return {"result": self.privileges}
        if method == "user.query":
            return {"result": [{k: v for k, v in u.items()} for u in self.users if _match(u, params)]}
        if method == "group.query":
            return {"result": list(self.groups)}
        if method == "user.create":
            assert not any(u["username"] == params[0]["username"] for u in self.users), "an existing user made again"
            assert not any(g["group"] == params[0]["username"] for g in self.groups), "an existing group made again"
            uid = 70 + len(self.users)
            self.users.append({"id": uid, **params[0]})
            self.groups.append({"id": 900 + uid, "group": params[0]["username"], "of": uid})
            return {"result": {"id": uid, **params[0]}}
        if method == "user.delete":
            [u] = [u for u in self.users if u.get("id") == params[0]]
            self.users.remove(u)
            if params[1].get("delete_group"):
                self.groups = [g for g in self.groups if g.get("of") != params[0]]
            return {"result": params[0]}
        if method == "api_key.query":
            return {"result": [{"id": k["id"], "name": k["name"], "username": k["username"]} for k in self.keys
                               if _match(k, params)]}
        if method == "api_key.create":
            assert not any(k["name"] == params[0]["name"] for k in self.keys), "an existing key name made again"
            kid = max([k["id"] for k in self.keys] + [0]) + 1
            key = f"{kid}-made-key-for-{params[0]['username']}"
            self.keys.append({**params[0], "id": kid, "key": key})
            return {"result": {"id": kid, **params[0], "key": key}}
        if method == "api_key.delete":
            [k] = [k for k in self.keys if k["id"] == params[0]]
            self.keys.remove(k)
            return {"result": True}
        if method == "system.info":
            return {"result": {"version": "25.10.7", "hostname": "truenas"}}
        if method in ("pool.query", "disk.query", "alert.list", "sharing.smb.query", "service.query"):
            return {"result": []}
        if method == "disk.temperatures":
            return {"result": {}}
        raise AssertionError(f"unexpected {method}")


def _match(row, params):
    """A TrueNAS query filter, the one shape Hisho sends: [[field, "=", value], ...]."""
    return all(row.get(f) == v for f, op, v in (params[0] if params else []))


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
    monkeypatch.setattr("hisho.fleet_config.local_name", lambda: "Test_Box")    # this machine: test-box
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


ADMIN = {"url": "192.0.2.21", "user": "truenas_admin", "password": "right-pass"}
#: what a live Hisho already has on this TrueNAS: its user (and group) and key
LIVE_USER = {"id": 5, "username": "hisho", "groups": [41]}
LIVE_KEY = {"id": 1, "name": "hisho", "username": "hisho", "key": "old"}


def test_sign_in_once_makes_a_read_only_user_and_key_named_after_this_machine(nas):
    mod, fake = nas
    out = mod.connect(dict(ADMIN), None)
    assert out["ok"] and out["entry"] == {"url": "192.0.2.21", "fingerprint": "AB:CD", "api_key": "1-made-key-for-hisho-test-box",
                                          "made": {"user": {"name": "hisho-test-box", "id": 70, "group": "hisho-test-box"},
                                                   "api_keys": [{"name": "hisho-test-box", "id": 1}]}}
    assert all(o == ("192.0.2.21", 443, "AB:CD") for o in fake.opened)       # every connection pinned
    assert fake.calls[0] == ("auth.login_ex", [{"mechanism": "PASSWORD_PLAIN", "username": "truenas_admin",
                                                "password": "right-pass"}])
    [created] = [p[0] for m, p in fake.calls if m == "user.create"]
    assert created == {"username": "hisho-test-box", "full_name": "Hisho (read only)", "group_create": True, "groups": [41],
                       "password_disabled": True, "smb": False}
    assert ("api_key.create", [{"name": "hisho-test-box", "username": "hisho-test-box"}]) in fake.calls
    assert "can only read" in out["message"] and "right-pass" not in json.dumps(out)
    assert "made-key" not in json.dumps(out["entry"]["made"])


def test_next_to_a_live_hisho_nothing_is_reused_and_taken_names_get_a_suffix(nas):
    mod, fake = nas
    fake.users = [dict(LIVE_USER), {"id": 6, "username": "hisho-test-box"}]       # also another test-box Hisho
    fake.groups += [{"id": 950, "group": "hisho-test-box-2"}]                       # a group with the next name
    fake.keys = [dict(LIVE_KEY), {"id": 2, "name": "hisho-test-box", "username": "hisho-test-box", "key": "other"}]
    before = json.dumps([fake.users, fake.groups, fake.keys])
    fake.login_ex = False                                     # an older 25.x: auth.login
    out = mod.connect(dict(ADMIN), None)
    assert ("auth.login", ["truenas_admin", "right-pass"]) in fake.calls
    [created] = [p[0]["username"] for m, p in fake.calls if m == "user.create"]
    assert created == "hisho-test-box-3"
    assert ("api_key.create", [{"name": "hisho-test-box-2", "username": "hisho-test-box-3"}]) in fake.calls
    assert out["entry"]["made"] == {"user": {"name": "hisho-test-box-3", "id": 72, "group": "hisho-test-box-3"},
                                    "api_keys": [{"name": "hisho-test-box-2", "id": 3}]}
    writes = [m for m, _ in fake.calls if m.endswith((".create", ".update", ".delete"))]
    assert writes == ["user.create", "api_key.create"]                     # nothing existing is changed
    old = json.loads(before)
    assert all(u in fake.users for u in old[0]) and all(g in fake.groups for g in old[1])
    assert all(k in fake.keys for k in old[2])


def test_without_a_read_only_group_the_key_is_the_admins_and_it_says_so(nas):
    mod, fake = nas
    fake.privileges = [FULL_PRIVILEGE]
    out = mod.connect(dict(ADMIN), None)
    assert out["entry"]["api_key"].endswith("for-truenas_admin")
    assert out["entry"]["made"] == {"api_keys": [{"name": "hisho-test-box", "id": 1}]}       # no user made
    assert "acts as truenas_admin" in out["message"] and "no Read-only Administrators group" in out["message"]


def test_a_read_only_key_that_cannot_read_falls_back_to_the_admin(nas):
    mod, fake = nas
    fake.ro_reads = False
    out = mod.connect(dict(ADMIN), None)
    made = [p[0] for m, p in fake.calls if m == "api_key.create"]
    assert [k["username"] for k in made] == ["hisho-test-box", "truenas_admin"]
    assert [k["name"] for k in made] == ["hisho-test-box", "hisho-test-box-2"]
    assert out["entry"]["api_key"].endswith("for-truenas_admin") and "could not read" in out["message"]
    assert [k["name"] for k in out["entry"]["made"]["api_keys"]] == ["hisho-test-box", "hisho-test-box-2"]


def test_remove_from_truenas_deletes_exactly_what_was_made(nas):
    mod, fake = nas
    fake.users = [dict(LIVE_USER)]
    fake.keys = [dict(LIVE_KEY)]
    entry = mod.connect(dict(ADMIN), None)["entry"]
    fake.keys.append({"id": 9, "name": "mine", "username": "truenas_admin", "key": "x"})
    before_users = [u for u in fake.users if u["username"] != "hisho-test-box"]
    fake.calls.clear()
    out = mod.disconnect(entry, {"user": "truenas_admin", "password": "right-pass"}, None)
    assert out["ok"] and "right-pass" not in out["message"]
    deletes = [(m, p) for m, p in fake.calls if m.endswith(".delete")]
    assert deletes == [("api_key.delete", [2]), ("user.delete", [entry["made"]["user"]["id"], {"delete_group": True}])]
    assert entry["made"]["user"]["id"] == 71
    assert fake.users == before_users and [k["name"] for k in fake.keys] == ["hisho", "mine"]
    assert not any(g["group"] == "hisho-test-box" for g in fake.groups)
    assert "deleted API key hisho-test-box, user hisho-test-box" in out["message"]
    assert all(o == ("192.0.2.21", 443, "AB:CD") for o in fake.opened)


def test_remove_says_what_is_already_gone_and_never_deletes_a_same_named_newcomer(nas):
    mod, fake = nas
    entry = mod.connect(dict(ADMIN), None)["entry"]
    fake.keys.clear()                                                      # the owner deleted the key by hand
    fake.users = [{"id": 99, "username": "hisho-test-box"}]               # and someone made a new user of that name
    out = mod.disconnect(entry, {"user": "truenas_admin", "password": "right-pass"}, None)
    assert out["ok"] and "already gone: API key hisho-test-box, user hisho-test-box" in out["message"]
    assert not [m for m, _ in fake.calls if m.endswith(".delete")] and fake.users[0]["id"] == 99


def test_remove_needs_what_hisho_made_and_a_remembered_certificate(nas):
    mod, fake = nas
    login = {"user": "truenas_admin", "password": "right-pass"}
    assert not mod.disconnect({"url": "192.0.2.21", "api_key": "K"}, login, None)["ok"]          # a key made by hand
    with pytest.raises(mod.TrueNASError, match="not a user Hisho makes"):
        mod.disconnect({"url": "192.0.2.21", "fingerprint": "AB:CD", "made": {"user": {"name": "truenas_admin", "id": 1}}},
                       login, None)
    with pytest.raises(mod.TrueNASError, match="remembers no certificate"):
        mod.disconnect({"url": "192.0.2.21", "made": {"api_keys": [{"name": "hisho-x", "id": 1}]}}, login, None)
    assert fake.calls == []


def test_the_machine_name_falls_back_to_the_hostname(addon, monkeypatch):
    mod = addons.provider(addon)
    monkeypatch.setattr("hisho.fleet_config.local_name", lambda: (_ for _ in ()).throw(RuntimeError()))
    monkeypatch.setattr(mod.socket, "gethostname", lambda: "A-Very_Long.Machine-Name-Indeed.lan")
    assert mod._machine() == "a-very-long"
    assert addon.manifest["entry_schema"]["made"] == "map?"
    assert set(addon.manifest["disconnect"]["fields"]) == {"user", "password"}


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


def test_sign_in_once_and_remove_through_core(fleet, nas, monkeypatch, tmp_path):
    monkeypatch.setattr(addons, "LOCAL_SECRETS", str(tmp_path / "secrets.env"))
    mod, fake = nas
    tn = addons.get("truenas")
    out = hconnect.connect(tn, "nas", {"url": "192.0.2.21", "user": "truenas_admin", "password": "right-pass"})
    assert out["ok"], out
    e = addons.read_config("truenas")["entries"]["nas"]
    assert e["fingerprint"] == "AB:CD" and "password" not in e and "user" not in e
    saved = open(addons.config_path("truenas")).read()
    assert "made-key" not in saved and "right-pass" not in saved
    assert e["made"]["user"]["name"] == "hisho-test-box"
    gone = hconnect.disconnect(tn, "nas", {"user": "truenas_admin", "password": "right-pass"})
    assert gone["ok"], gone
    assert "nas" not in (addons.read_config("truenas").get("entries") or {})
    assert fake.keys == [] and not any(u["username"] == "hisho-test-box" for u in fake.users)
