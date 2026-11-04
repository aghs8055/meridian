"""Check that the answer key is accurate.

Confirms that every keyed vulnerability fires, every secured decoy rejects the attacker, and that
no other cross-organization read or write is possible. Exits with status 1 if any check fails.

Run: python selftest.py
"""
import sys

import app
from fastapi.testclient import TestClient

c = TestClient(app.app)
A = app


def login(email):
    return {"Authorization": "Bearer " + c.post("/api/login", json={"email": email, "password": "Passw0rd!"}).json()["access_token"]}


MAL = ALICE = None


def reset():
    """Reseed AND re-login — reset() wipes the token table, so headers must be refreshed."""
    global MAL, ALICE
    c.post("/api/admin/reset")
    MAL = login("mallory@zenith.test")   # attacker, Org B
    ALICE = login("alice@acme.test")     # victim, Org A


reset()

keyed = []


def k(name, cond, note=""):
    keyed.append((name, bool(cond), note))


# Keyed vulnerabilities: reads
r = c.get(f"/api/accounts/{A.ACC_A1}/transactions/{A.TXN_A1}/receipts/{A.RCP_A1}", headers=MAL)
k("K1 deep-chain receipt", r.status_code == 200 and "CONFIDENTIAL" in r.json().get("content", ""))

r = c.post(f"/api/cards/{A.CARD_A1}/reveal", headers=MAL)
k("K2 PAN reveal", r.status_code == 200 and r.json().get("pan") == "4242424242424242")

r = c.get(f"/api/accounts/{A.ACC_A1}/transactions", headers=MAL)
sib = c.get(f"/api/accounts/{A.ACC_A1}", headers=MAL)
k("K3 txn-list (sibling secured)", r.status_code == 200 and len(r.json()["transactions"]) > 0 and sib.status_code == 403)

r = c.get(f"/api/documents/{A.DOC_A1}", headers=MAL)
k("K4 stale-grant doc read", r.status_code == 200 and "CONFIDENTIAL" in r.json().get("content", ""))

r = c.get(f"/api/beneficiaries/{A.BEN_A1}", headers=MAL)
k("K5 cross-org beneficiary", r.status_code == 200 and r.json().get("iban") == "US99INITECH01")

# Keyed vulnerabilities: writes, verified by the victim reading the object again
reset()
c.post(f"/api/accounts/{A.ACC_A1}/freeze", headers=MAL)
frozen = c.get(f"/api/accounts/{A.ACC_A1}", headers=ALICE).json()["frozen"]
resp = c.post(f"/api/accounts/{A.ACC_A1}/freeze", headers=MAL)
k("K6 forbidden-but-done", resp.status_code == 403 and frozen is True)

reset()
before = c.get(f"/api/accounts/{A.ACC_A1}", headers=ALICE).json()["daily_limit"]
w = c.patch(f"/api/accounts/{A.ACC_A1}/limits", headers=MAL, json={"daily_limit": 1})
after = c.get(f"/api/accounts/{A.ACC_A1}", headers=ALICE).json()["daily_limit"]
k("K7 silent write", w.json() == {"status": "ok"} and before != after and after == 1)

reset()
w = c.patch(f"/api/transfers/{A.TRF_A_DRAFT}", headers=MAL, json={"reference": "PWN"})
after = c.get(f"/api/transfers/{A.TRF_A_DRAFT}", headers=ALICE).json()["reference"]
k("K8 tiny-diff in large obj", w.status_code == 200 and after == "PWN" and len(str(w.json())) > 600)

reset()
c.post(f"/api/cards/{A.CARD_A1}/freeze", headers=MAL)
cf = c.get(f"/api/cards/{A.CARD_A1}", headers=ALICE).json()["frozen"]
k("K9 silent card freeze", cf is True)

# Keyed vulnerabilities: leaks through filters and query options
reset()
r = c.get(f"/api/reports/cashflow?org_id={A.ORG_A}", headers=MAL)
k("K10 cashflow agg leak", r.status_code == 200 and len(r.json()["rows"]) >= 2)

r = c.get(f"/api/transactions?beneficiary_id={A.BEN_A1}", headers=MAL)
k("K11 search-filter leak", r.status_code == 200 and len(r.json()["transactions"]) > 0)

r = c.get(f"/api/accounts/{A.ACC_A1}?expand=transactions", headers=MAL)
plain = c.get(f"/api/accounts/{A.ACC_A1}", headers=MAL)
k("K12 expand-bypass", r.status_code == 200 and plain.status_code == 403 and r.json().get("transactions"))

# Keyed vulnerabilities: state-dependent, multi-step and asynchronous
reset()
r = c.post(f"/api/transfers/{A.TRF_A_PEND}/approve", headers=MAL)
k("K13 cross-org state approve", r.status_code == 200 and r.json()["status"] == "approved")

reset()
r = c.post("/api/transfers/batch", headers=MAL, json={"transfer_ids": [A.TRF_B1, A.TRF_A_PEND]})
victim_status = c.get(f"/api/transfers/{A.TRF_A_PEND}", headers=ALICE).json()["status"]
k("K14 batch partial-authz", r.status_code == 200 and victim_status == "approved")

reset()
e = c.post("/api/exports", headers=MAL, json={"resource": "accounts", "org_id": A.ORG_A}).json()
d = c.get(f"/api/exports/{e['id']}/download", headers=MAL)
got_a = any(row.get("org_id") == A.ORG_A for row in d.json().get("rows", []))
k("K15 async export scope", d.status_code == 200 and got_a)

reset()
r = c.post(f"/api/transfers/{A.TRF_B1}/commit", headers=MAL, json={"source_account_id": A.ACC_A1})
k("K16 TOCTOU step-swap", r.status_code == 200 and r.json()["source_account_id"] == A.ACC_A1)


# Secured decoys: must reject the attacker
reset()
decoys = [
    ("GET", f"/api/accounts/{A.ACC_A1}"),
    ("DELETE", f"/api/accounts/{A.ACC_A1}"),
    ("GET", f"/api/accounts/{A.ACC_A1}/balance"),
    ("GET", f"/api/accounts/{A.ACC_A1}/statement"),
    ("POST", f"/api/accounts/{A.ACC_A1}/unfreeze"),
    ("GET", f"/api/transfers/{A.TRF_A_DRAFT}"),
    ("DELETE", f"/api/transfers/{A.TRF_A_DRAFT}"),
    ("POST", f"/api/transfers/{A.TRF_A_PEND}/reject"),
    ("POST", f"/api/transfers/{A.TRF_A_PEND}/cancel"),
    ("POST", f"/api/transfers/{A.TRF_A_DRAFT}/submit"),
    ("GET", f"/api/transactions/{A.TXN_A1}"),
    ("GET", f"/api/cards/{A.CARD_A1}"),
    ("DELETE", f"/api/cards/{A.CARD_A1}"),
    ("PATCH", f"/api/cards/{A.CARD_A1}/limit"),
    ("GET", f"/api/statements/{A.STM_A1}"),
    ("DELETE", f"/api/documents/{A.DOC_A1}"),
    ("DELETE", f"/api/beneficiaries/{A.BEN_A1}"),
    ("GET", f"/api/orgs/{A.ORG_A}"),
    ("PATCH", f"/api/orgs/{A.ORG_A}"),
    ("GET", f"/api/orgs/{A.ORG_A}/members"),
    ("GET", f"/api/orgs/{A.ORG_A}/audit-log"),
    ("PATCH", f"/api/memberships/{A.U_ALICE}/role"),
    ("DELETE", f"/api/memberships/{A.U_ALICE}"),
    ("GET", f"/api/webhooks/{A.WH_A1}"),
    ("DELETE", f"/api/webhooks/{A.WH_A1}"),
]
# Valid bodies, so that the request reaches the authorization check instead of failing with 422.
bodies = {f"/api/cards/{A.CARD_A1}/limit": {"spend_limit": 1},
          f"/api/memberships/{A.U_ALICE}/role": {"role": "viewer"},
          f"/api/orgs/{A.ORG_A}": {"name": "x"}}
decoy_fail = []
for m, path in decoys:
    body = bodies.get(path, {}) if m in ("PATCH", "POST") else None
    resp = c.request(m, path, headers=MAL, json=body)
    if resp.status_code not in (403, 404):
        decoy_fail.append((m, path, resp.status_code))

# Sweep: no other write may change the victim's data
reset()
write_sweep = [
    ("POST", f"/api/accounts/{A.ACC_A1}/unfreeze", None, f"/api/accounts/{A.ACC_A1}", ALICE, "frozen"),
    ("PATCH", f"/api/cards/{A.CARD_A1}/limit", {"spend_limit": 9}, f"/api/cards/{A.CARD_A1}", ALICE, "spend_limit"),
    ("POST", f"/api/transfers/{A.TRF_A_PEND}/reject", None, f"/api/transfers/{A.TRF_A_PEND}", ALICE, "status"),
    ("POST", f"/api/transfers/{A.TRF_A_PEND}/cancel", None, f"/api/transfers/{A.TRF_A_PEND}", ALICE, "status"),
    ("PATCH", f"/api/memberships/{A.U_ALICE}/role", {"role": "viewer"}, None, None, None),
]
unexpected_write = []
for m, path, body, verify_path, vhdr, field in write_sweep:
    if verify_path:
        before = c.get(verify_path, headers=vhdr).json().get(field)
    c.request(m, path, headers=MAL, json=body)
    if verify_path:
        after = c.get(verify_path, headers=vhdr).json().get(field)
        if before != after:
            unexpected_write.append((m, path, f"{before}->{after}"))

# Sweep: no other GET endpoint may return the victim's objects
reset()
keyed_get = {f"/api/accounts/{A.ACC_A1}/transactions/{A.TXN_A1}/receipts/{A.RCP_A1}",
             f"/api/accounts/{A.ACC_A1}/transactions",
             f"/api/documents/{A.DOC_A1}", f"/api/beneficiaries/{A.BEN_A1}",
             f"/api/reports/cashflow", f"/api/transactions",
             f"/api/accounts/{A.ACC_A1}"}  # expand variant keyed
victim_markers = ["Acme", "US00ACME", "4242", "Initech", "CONFIDENTIAL", A.ORG_A, "US99INITECH"]
sweep_get = [
    f"/api/accounts/{A.ACC_A2}", f"/api/accounts/{A.ACC_A1}/balance",
    f"/api/accounts/{A.ACC_A1}/statement", f"/api/transfers/{A.TRF_A_EXEC}",
    f"/api/statements/{A.STM_A1}", f"/api/cards/{A.CARD_A1}",
    f"/api/orgs/{A.ORG_A}", f"/api/webhooks/{A.WH_A1}",
]
unexpected = []
for path in sweep_get:
    resp = c.get(path, headers=MAL)
    if resp.status_code == 200 and any(mk in resp.text for mk in victim_markers):
        unexpected.append(("GET", path, resp.status_code))

# Report
print("\n================ KEYED VULNS ================")
for name, ok, note in keyed:
    print(f"  [{'FIRE' if ok else 'FAIL'}] {name}{(' — ' + note) if note else ''}")
nfire = sum(1 for _, ok, _ in keyed if ok)
print(f"  keyed firing: {nfire}/{len(keyed)}")

print("\n================ DECOYS (must reject) ================")
print("  all reject" if not decoy_fail else f"  LEAKY DECOYS: {decoy_fail}")

print("\n================ SWEEP: unexpected (non-keyed) cross-org reads ================")
print("  none found" if not unexpected else f"  UNEXPECTED READS: {unexpected}")

print("\n================ SWEEP: unexpected (non-keyed) cross-org writes ================")
print("  none found" if not unexpected_write else f"  UNEXPECTED WRITES: {unexpected_write}")

print("\nSUMMARY:",
      f"{nfire}/{len(keyed)} keyed fire,",
      f"{len(decoy_fail)} leaky decoys,",
      f"{len(unexpected) + len(unexpected_write)} unexpected vulns")
sys.exit(0 if nfire == len(keyed) and not decoy_fail and not unexpected and not unexpected_write else 1)
