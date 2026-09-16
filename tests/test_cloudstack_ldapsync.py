#!/usr/bin/env python3
"""
Tests for files/cloudstack-ldapsync.py.

There is no test framework or CI in this repo, so this is a self-contained
script: run `python3 tests/test_cloudstack_ldapsync.py`, exit status 0 means
everything passed.  ldap3, cs and click are stubbed out, so no dependencies are
needed beyond the standard library.

Coverage is deliberately weighted towards the paths that destroy data: the
disable/stamp/delete lifecycle, the two guards in front of it, and the LDAP
paging that decides who looks absent in the first place.
"""

import importlib.util
import os
import sys
import tempfile
import types
from datetime import datetime, timedelta, timezone

# --- stub the third party imports before loading the script under test --------

ldap3 = types.ModuleType("ldap3")
ldap3.ALL_ATTRIBUTES = "*"
ldap3.Server = lambda *a, **k: None
ldap3.Connection = lambda *a, **k: None
sys.modules["ldap3"] = ldap3

cs = types.ModuleType("cs")
cs.CloudStack = object
sys.modules["cs"] = cs

click = types.ModuleType("click")
click.command = lambda *a, **k: (lambda f: f)
click.option = lambda *a, **k: (lambda f: f)
click.Path = lambda *a, **k: None
sys.modules["click"] = click

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "files", "cloudstack-ldapsync.py")
spec = importlib.util.spec_from_file_location("ldapsync", SCRIPT)
ldapsync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ldapsync)

TMP = tempfile.mkdtemp(prefix="ldapsync-tests-")
CMK = os.path.join(TMP, "cmk")
CONF = os.path.join(TMP, "ldapsync.conf")
open(CMK, "w").write("[localcloud]\nurl=http://x/client/api\napikey=k\nsecretkey=s\n")

FAILURES = []
PASSES = 0


def chk(label, got, want):
    global PASSES
    if got == want:
        PASSES += 1
    else:
        FAILURES.append(f"{label}\n     got={got!r}\n    want={want!r}")


def raises(label, fn, needle):
    global PASSES
    try:
        fn()
        got = "no exception"
    except Exception as e:  # noqa: BLE001 - the script raises bare Exceptions
        got = str(e)
    if needle.lower() in got.lower():
        PASSES += 1
    else:
        FAILURES.append(f"{label}\n     got={got!r}\n    want substring {needle!r}")


# --- fakes -------------------------------------------------------------------


class FakeCloudStack:
    """In-memory stand-in recording every mutating call as (op, account name)."""

    def __init__(self, accounts):
        self.accounts = accounts
        self.calls = []

    def _by_id(self, account_id):
        return next(a for a in self.accounts.values() if a["id"] == account_id)

    def listAccounts(self, **kwargs):
        # The real API filters on id; the delete path re-reads a single account
        # through it, so returning everything here would hide a positional bug.
        wanted = kwargs.get("id")
        return {
            "account": [
                dict(
                    a,
                    # Copied, not shared: the real API returns freshly parsed
                    # JSON on every call, so a caller's snapshot is independent
                    # of later server-side changes.  Sharing the dict hid the
                    # stale-snapshot revert entirely.
                    accountdetails=dict(a.get("accountdetails") or {}),
                    user=[
                        {
                            "id": "u-" + a["name"],
                            "username": a["name"],
                            "firstname": "A",
                            "lastname": "B",
                            "email": a["name"] + "@example.com",
                            "usersource": "saml2",
                        }
                    ],
                )
                for a in self.accounts.values()
                if wanted is None or a["id"] == wanted
            ]
        }

    def listProjects(self, **kwargs):
        return {}

    def listRoles(self, **kwargs):
        return {"role": [{"id": "r-user", "name": "User"}, {"id": "r-root", "name": "Root Admin"}]}

    def listIdps(self, **kwargs):
        return {"idp": [{"id": "idp1", "orgName": "Okta"}]}

    def disableAccount(self, id, lock):
        self._by_id(id)["state"] = "disabled"
        self.calls.append(("disable", self._by_id(id)["name"]))

    def enableAccount(self, id):
        self._by_id(id)["state"] = "enabled"
        self.calls.append(("enable", self._by_id(id)["name"]))

    def deleteAccount(self, id):
        account = self._by_id(id)
        self.calls.append(("delete", account["name"]))
        del self.accounts[account["name"]]

    def updateAccount(self, id, **kwargs):
        """
        Mirrors CloudStack 4.22.1.1, verified against a live management server:

          * newname is MANDATORY.  Omitting it fails with cserrorcode 4250
            regardless of how the account is identified, and it renames the
            account, so it has to match the name the server already holds.
          * The details map is only touched when the parameter is supplied.
          * Details MERGE rather than replace: the supplied keys are putAll'd
            over the current map, so a key cannot be removed by leaving it out.
            An empty string is stored as an empty string; there is no way to
            delete a key through this API.
        """
        account = self._by_id(id)
        if "newname" not in kwargs:
            raise Exception(
                "HTTP 530 response from CloudStack, error: "
                "{'errorcode': 530, 'cserrorcode': 4250, 'errortext': "
                "'Unable to update account " + account["name"] + "'}"
            )
        if kwargs["newname"] != account["name"]:
            raise AssertionError(
                f"newname renames the account: {account['name']!r} -> {kwargs['newname']!r}"
            )
        if "accountdetails" in kwargs:
            account["accountdetails"] = {**account["accountdetails"], **kwargs["accountdetails"]}
            self.calls.append(("stamp", account["name"]))
        else:
            self.calls.append(("update", account["name"]))

    def authorizeSamlSso(self, **kwargs):
        pass

    def updateUser(self, **kwargs):
        pass


class FakeConnection:
    """Stands in for a bound ldap3 Connection with a paged_search extension."""

    def __init__(self, entries, result=None):
        self._entries = entries
        self.result = result if result is not None else {"result": 0, "description": "success"}
        self.pages = 0
        self.extend = types.SimpleNamespace(standard=types.SimpleNamespace(paged_search=self._paged_search))

    def _paged_search(self, search_base, search_filter, attributes, paged_size, generator, paged_criticality=False):
        assert generator is True
        assert paged_size == ldapsync.LDAP_PAGE_SIZE
        # Advisory paging is what let a non-supporting server answer with one
        # silently truncated page and result code 0.
        self.criticality = paged_criticality
        for i in range(0, len(self._entries), paged_size):
            self.pages += 1
            for entry in self._entries[i : i + paged_size]:
                yield entry


def entry(uid):
    return {"type": "searchResEntry", "dn": f"uid={uid},ou=users", "raw_attributes": {"uid": [uid.encode()]}}


def account(name, state="enabled", since=None, role="User"):
    details = {} if since is None else {ldapsync.DISABLED_SINCE_KEY: since.isoformat()}
    return {"id": "a-" + name, "name": name, "state": state, "rolename": role, "accountdetails": details}


def ldap_user(name, role="User"):
    return ldapsync.User(
        username=name,
        fname="A",
        lname="B",
        email=name + "@example.com",
        account_uuid=None,
        uuid=None,
        role=role,
        usersource="saml2",
        state="enabled",
    )


CAPTURED = {}


def run(accounts, ldap_names, days=30, percent=25, dry_run=False, roles=None, max_delete=5, client_cls=None):
    """Drive sync() end to end against the fakes and return the fake client."""
    open(CONF, "w").write(
        "[ldap]\nproject_groups=\n"
        "[cloudstack]\nignore_users=admin\nignore_projects=\nnetwork_groups=\n"
        f"delete_disabled_after_days={days}\nmax_disable_percent={percent}\n"
        f"max_delete_per_run={max_delete}\n"
    )
    client = (client_cls or FakeCloudStack)({a["name"]: a for a in accounts})
    CAPTURED["client"] = client  # captured even when sync() raises
    ldapsync.CloudStack = lambda **kwargs: client
    roles = roles or {}
    ldapsync.fetch_ldap = lambda config: ({n: ldap_user(n, roles.get(n, "User")) for n in ldap_names}, {})
    ldapsync.sync(CONF, CMK, dry_run)
    return client


def ops(client, kind):
    return [name for op, name in client.calls if op == kind]


# --- LDAP paging -------------------------------------------------------------

print("== LDAP paging ==")
many = [entry(f"u{i}") for i in range(1250)]
conn = FakeConnection(many)
chk("all entries returned, not capped at one page", len(ldapsync.ldap_search(conn, "ou=users", "user")), 1250)
chk("search was paged", conn.pages, 3)
chk("paging is critical, so a server that ignores it must refuse", conn.criticality, True)

raises(
    "sizeLimitExceeded aborts instead of silently truncating",
    lambda: ldapsync.ldap_search(
        FakeConnection(many[:1000], {"result": 4, "description": "sizeLimitExceeded", "message": "limit"}),
        "ou=users",
        "user",
    ),
    "sizeLimitExceeded",
)
raises(
    "an empty directory aborts",
    lambda: ldapsync.ldap_search(FakeConnection([]), "ou=users", "user"),
    "returned no entries",
)
chk(
    "referrals are skipped",
    len(ldapsync.ldap_search(FakeConnection([entry("a"), {"type": "searchResRef"}, entry("b")]), "ou=u", "user")),
    2,
)

# --- disable / stamp / delete lifecycle --------------------------------------

print("== lifecycle ==")
now = datetime.now(timezone.utc)

client = run([account("alice"), account("bob")], ["alice"])
chk("absent user is disabled and stamped", client.calls, [("disable", "bob"), ("stamp", "bob")])
chk("absent user is not deleted", "bob" in client.accounts, True)

client = run([account("alice"), account("bob", "disabled", now - timedelta(days=29))], ["alice"])
chk("no churn inside the window", client.calls, [])

client = run([account("alice"), account("bob", "disabled", now - timedelta(days=30))], ["alice"])
chk("deleted once the window elapses", ops(client, "delete"), ["bob"])

client = run([account("alice"), account("bob", "disabled")], ["alice"])
chk("already-disabled but unstamped starts the clock now", client.calls, [("stamp", "bob")])
chk("and survives its first run", "bob" in client.accounts, True)

client = run([account("alice"), account("bob", "disabled", now - timedelta(days=10))], ["alice", "bob"])
chk("reinstated user is re-enabled and unstamped", client.calls, [("enable", "bob"), ("stamp", "bob")])
chk("stamp cleared", client.accounts["bob"]["accountdetails"][ldapsync.DISABLED_SINCE_KEY], "")

client = run([account("alice"), account("bob", "enabled", now - timedelta(days=99))], ["alice"])
chk("re-disabled user gets a fresh window, not the old stamp", ops(client, "delete"), [])
chk("and is disabled and restamped", client.calls, [("stamp", "bob"), ("disable", "bob"), ("stamp", "bob")])

client = run([account("alice"), account("bob", "disabled", now - timedelta(days=999))], ["alice"], days=0)
chk("retention 0 never deletes", client.calls, [])

bad = {"id": "a-bob", "name": "bob", "state": "disabled", "rolename": "User",
       "accountdetails": {ldapsync.DISABLED_SINCE_KEY: "garbage"}}
client = run([account("alice"), bad], ["alice"])
chk("unparseable stamp is rewritten, not treated as ancient", client.calls, [("stamp", "bob")])

# --- stale stamps left by an out-of-band re-enable ---------------------------

print("== stale stamps ==")
client = run([account("alice"), account("bob", "enabled", now - timedelta(days=99))], ["alice", "bob"])
chk("stamp on an enabled account is cleared", ops(client, "stamp"), ["bob"])
chk("stamp value cleared", client.accounts["bob"]["accountdetails"][ldapsync.DISABLED_SINCE_KEY], "")
chk("and the account is not deleted", "bob" in client.accounts, True)

# --- administrative lock is not ours to lift ---------------------------------

print("== locked accounts ==")
chk("locked counts as matching", ldapsync.user_match_state(ldap_user("bob"), 
    ldapsync.User(username="bob", fname="A", lname="B", email="e", account_uuid="a", uuid="u",
                  role="User", usersource="saml2", state="locked")), True)
client = run([account("alice"), account("bob", "locked")], ["alice", "bob"])
chk("a locked account is left alone", ops(client, "enable"), [])
chk("locked account still locked", client.accounts["bob"]["state"], "locked")

# --- account details survive unrelated updates --------------------------------

print("== accountdetails ==")
keeper = account("bob")
keeper["accountdetails"] = {"unrelated": "keep-me"}
client = run([account("alice"), keeper], ["alice", "bob"], roles={"bob": "Root Admin"})
chk("a role change is issued", ops(client, "update"), ["bob"])
chk("unrelated details survive it", client.accounts["bob"]["accountdetails"], {"unrelated": "keep-me"})

stamped = account("bob", "disabled", now - timedelta(days=1))
stamped["accountdetails"]["unrelated"] = "keep-me"
client = run([account("alice"), stamped], ["alice", "bob"])
chk("clearing the stamp leaves other keys alone",
    client.accounts["bob"]["accountdetails"]["unrelated"], "keep-me")
chk("and the stamp is cleared by value, not removal",
    client.accounts["bob"]["accountdetails"][ldapsync.DISABLED_SINCE_KEY], "")

# --- guards ------------------------------------------------------------------

print("== disable guard ==")


def many_accounts(total, in_ldap, **kwargs):
    accounts = [account(f"u{i}") for i in range(total)]
    return run(accounts, [f"u{i}" for i in range(in_ldap)], **kwargs)


raises("a mass departure aborts", lambda: many_accounts(100, 40), "exceeds max_disable_percent")
chk("nothing was modified before aborting", CAPTURED["client"].calls, [])
chk("an ordinary departure proceeds", len(ops(many_accounts(100, 90), "disable")), 10)
chk("percent 0 disables the guard", len(ops(many_accounts(100, 0, percent=0), "disable")), 100)

chk("floor is 3", ldapsync.MIN_DISABLE_BEFORE_GUARD, 3)
chk("1 of 2 leaving is 50% but under the floor", len(ops(many_accounts(2, 1), "disable")), 1)
chk("3 of 4 leaving sits at the floor", len(ops(many_accounts(4, 1), "disable")), 3)
raises("4 of 4 clears the floor and aborts", lambda: many_accounts(4, 0), "exceeds max_disable_percent")

print("== delete guard ==")


def expiring(total, expiring_count, **kwargs):
    """total accounts, all absent from LDAP; expiring_count are past the window."""
    accounts = [
        account(f"u{i}", "disabled", now - timedelta(days=99 if i < expiring_count else 1))
        for i in range(total)
    ]
    return run(accounts, [], **kwargs)


chk("an expiry within the cap proceeds", len(ops(expiring(100, 5), "delete")), 5)
chk("a bulk expiry is refused entirely", ops(expiring(100, 60), "delete"), [])
chk("refusing deletes nothing at all, not just the excess", ops(CAPTURED["client"], "delete"), [])
chk("0 disables the delete cap", len(ops(expiring(100, 60, max_delete=0), "delete")), 60)

# The disable guard's small-count floor must NOT apply to deletion: sharing it
# meant max_delete_per_run=1 still destroyed 3 accounts per run, and on an
# hourly cron across several nodes that is not a ceiling at all.
chk("no small-count bypass on deletion", ops(expiring(4, 3, max_delete=1), "delete"), [])

# A refused deletion must not take the rest of the sync down with it -- unlike
# the disable guard, a bulk expiry says nothing about the directory read.
accounts = [account(f"u{i}", "disabled", now - timedelta(days=99)) for i in range(60)]
accounts.append(account("departing"))
client = run(accounts, [], max_delete=5)
chk("a refused deletion still lets the rest of the run proceed", ops(client, "disable"), ["departing"])
chk("and still deletes nothing", ops(client, "delete"), [])

print("== locked accounts are a durable hold ==")

# Both the delete and stamping passes previously selected on state != "enabled",
# which swept in "locked".  Nothing here ever lifts a lock, so deleting a locked
# account destroys exactly the data an admin deliberately froze.
client = run([account("alice"), account("legalhold", "locked")], ["alice"])
chk("a locked account absent from LDAP is not stamped", ops(client, "stamp"), [])
chk("and is not disabled", ops(client, "disable"), [])
chk("and keeps its state", client.accounts["legalhold"]["state"], "locked")

client = run([account("alice"), account("legalhold", "locked", now - timedelta(days=99))], ["alice"])
chk("a long-locked account is never deleted", ops(client, "delete"), [])

# A stamp surviving across a lock would delete the account the moment an admin
# unlocked it back to disabled, with no retention window at all.
chk("a stamp on a locked account is cleared", ops(client, "stamp"), ["legalhold"])
chk("cleared by value", client.accounts["legalhold"]["accountdetails"][ldapsync.DISABLED_SINCE_KEY], "")

print("== clock sanity ==")

client = run([account("bob", "disabled", now + timedelta(days=400))], [])
chk("a stamp dated in the future is not acted on", ops(client, "delete"), [])

print("== re-read before deleting ==")


class ReEnablingCloudStack(FakeCloudStack):
    """Another node re-enables the account between the snapshot and the delete."""

    def listAccounts(self, **kwargs):
        result = super().listAccounts(**kwargs)
        if kwargs.get("id") == "a-bob":
            self.accounts["bob"]["state"] = "enabled"
            result = super().listAccounts(**kwargs)
        return result


client = run(
    [account("bob", "disabled", now - timedelta(days=99))], [], client_cls=ReEnablingCloudStack
)
chk("an account re-enabled mid-run is not deleted on a stale snapshot", ops(client, "delete"), [])

print("== a detail rotated mid-run is not reverted ==")


class RgwRotationCloudStack(FakeCloudStack):
    """
    A detail that EXISTED at snapshot time is rotated mid-run -- on our
    deployment that map holds live Ceph RGW credentials.  Details merge, so
    resending the run-start snapshot overwrites the new value with the old one.
    """

    def listAccounts(self, **kwargs):
        if kwargs.get("id"):  # the re-read, i.e. after the snapshot was taken
            self.accounts["bob"]["accountdetails"]["ceph-rgw-accesskey"] = "ROTATED"
        return super().listAccounts(**kwargs)


stale = account("bob")
stale["accountdetails"] = {"ceph-rgw-accesskey": "ORIGINAL"}
client = run([account("alice"), stale], ["alice"], client_cls=RgwRotationCloudStack)
chk("bob was stamped", ops(client, "stamp"), ["bob"])
chk("a credential rotated after the snapshot is not reverted",
    client.accounts["bob"]["accountdetails"].get("ceph-rgw-accesskey"), "ROTATED")
chk("and the stamp still landed alongside it",
    ldapsync.DISABLED_SINCE_KEY in client.accounts["bob"]["accountdetails"], True)

print("== shipped defaults ==")

# Deletion is the irreversible half and is opt-in.  This guards the role's own
# default, which the harness above overrides on every run and so never covers.
_defaults = open(os.path.join(os.path.dirname(__file__), "..", "defaults", "main.yml")).read()
chk("the role ships with deletion disabled",
    "cloudstack_saml_delete_disabled_after_days: 0" in _defaults, True)
chk("a config of 0 deletes nothing even when accounts are long expired",
    ops(run([account("bob", "disabled", now - timedelta(days=999))], [], days=0), "delete"), [])

print("== config validation ==")

raises(
    "a non-integer setting names the key rather than tracebacking",
    lambda: run([account("alice")], ["alice"], days="thirty"),
    "delete_disabled_after_days",
)

# --- report ------------------------------------------------------------------

print()
if FAILURES:
    for f in FAILURES:
        print(f"FAIL {f}")
    print(f"\n{PASSES} passed, {len(FAILURES)} FAILED")
    sys.exit(1)
print(f"{PASSES} assertions passed")
