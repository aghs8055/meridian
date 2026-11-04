"""Meridian: a multi-organization treasury API with intentionally embedded BOLA vulnerabilities.

Every route requires a bearer token. Two organizations share the system, and transfers go
through an approval workflow, so most authorization rules depend on organization membership and
object state rather than plain ownership.

State is kept in memory and reseeded on startup and by POST /api/admin/reset.

Endpoint docstrings become the public OpenAPI descriptions and are kept neutral on purpose. The
location of each vulnerability is marked with a `# KEY:` comment and documented in ANSWER_KEY.md.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

app = FastAPI(
    title="Meridian Treasury API",
    version="2.0.0",
    description="Multi-organization treasury and payments platform.",
)

ORG_A = "org-acme-1111"
ORG_B = "org-zenith-2222"

U_ALICE = "11111111-aaaa-4aaa-8aaa-111111111111"
U_BOB = "22222222-bbbb-4bbb-8bbb-222222222222"
U_CAROL = "33333333-cccc-4ccc-8ccc-333333333333"
U_MALLORY = "44444444-dddd-4ddd-8ddd-444444444444"

ACC_A1 = "acc-a1-0000-4000-8000-000000000001"
ACC_A2 = "acc-a2-0000-4000-8000-000000000002"
ACC_B1 = "acc-b1-0000-4000-8000-000000000003"

TXN_A1 = "txn-a1-0000-4000-8000-000000000001"
TXN_A2 = "txn-a2-0000-4000-8000-000000000002"
TXN_B1 = "txn-b1-0000-4000-8000-000000000003"
RCP_A1 = "rcp-a1-0000-4000-8000-000000000001"

TRF_A_DRAFT = "trf-ad-0000-4000-8000-000000000001"
TRF_A_PEND = "trf-ap-0000-4000-8000-000000000002"
TRF_A_EXEC = "trf-ae-0000-4000-8000-000000000003"
TRF_B1 = "trf-b1-0000-4000-8000-000000000004"

BEN_A1 = "ben-a1-0000-4000-8000-000000000001"
BEN_B1 = "ben-b1-0000-4000-8000-000000000002"

CARD_A1 = "card-a1-0000-4000-8000-00000000001"
CARD_B1 = "card-b1-0000-4000-8000-00000000002"

STM_A1 = "stm-a1-0000-4000-8000-000000000001"
DOC_A1 = "doc-a1-0000-4000-8000-000000000001"
GRANT_B = "grant-b-0000-4000-8000-00000000001"
WH_A1 = "wh-a1-0000-4000-8000-0000000000001"


def _seed() -> dict:
    """Build a fresh world (called at import and by POST /api/admin/reset)."""
    orgs = {
        ORG_A: {"id": ORG_A, "name": "Acme Capital", "tier": "enterprise"},
        ORG_B: {"id": ORG_B, "name": "Zenith Holdings", "tier": "standard"},
    }
    users = {
        U_ALICE: {"id": U_ALICE, "org_id": ORG_A, "role": "admin", "email": "alice@acme.test",
                  "name": "Alice Admin", "password": "Passw0rd!"},
        U_BOB: {"id": U_BOB, "org_id": ORG_A, "role": "initiator", "email": "bob@acme.test",
                "name": "Bob Initiator", "password": "Passw0rd!"},
        U_CAROL: {"id": U_CAROL, "org_id": ORG_A, "role": "approver", "email": "carol@acme.test",
                  "name": "Carol Approver", "password": "Passw0rd!"},
        U_MALLORY: {"id": U_MALLORY, "org_id": ORG_B, "role": "admin", "email": "mallory@zenith.test",
                    "name": "Mallory Admin", "password": "Passw0rd!"},
    }
    accounts = {
        ACC_A1: {"id": ACC_A1, "org_id": ORG_A, "label": "Acme Operating", "currency": "USD",
                 "balance": 4820000, "frozen": False, "daily_limit": 100000, "iban": "US00ACME0001"},
        ACC_A2: {"id": ACC_A2, "org_id": ORG_A, "label": "Acme Payroll", "currency": "USD",
                 "balance": 1230000, "frozen": False, "daily_limit": 250000, "iban": "US00ACME0002"},
        ACC_B1: {"id": ACC_B1, "org_id": ORG_B, "label": "Zenith Main", "currency": "USD",
                 "balance": 95000, "frozen": False, "daily_limit": 50000, "iban": "US00ZEN0001"},
    }
    transactions = {
        TXN_A1: {"id": TXN_A1, "account_id": ACC_A1, "amount": -52000, "memo": "Vendor wire — Initech",
                 "beneficiary_id": BEN_A1, "posted_at": "2026-05-02T10:00:00Z", "receipt_id": RCP_A1},
        TXN_A2: {"id": TXN_A2, "account_id": ACC_A2, "amount": -18000, "memo": "Payroll run",
                 "beneficiary_id": BEN_A1, "posted_at": "2026-05-15T10:00:00Z", "receipt_id": None},
        TXN_B1: {"id": TXN_B1, "account_id": ACC_B1, "amount": -3000, "memo": "Office supplies",
                 "beneficiary_id": BEN_B1, "posted_at": "2026-05-20T10:00:00Z", "receipt_id": None},
    }
    receipts = {
        RCP_A1: {"id": RCP_A1, "transaction_id": TXN_A1,
                 "content": "CONFIDENTIAL receipt: Initech invoice #4471, $520.00, acct ****0001"},
    }
    transfers = {
        TRF_A_DRAFT: _transfer(TRF_A_DRAFT, ORG_A, ACC_A1, "draft", 25000, U_BOB),
        TRF_A_PEND: _transfer(TRF_A_PEND, ORG_A, ACC_A1, "pending_approval", 80000, U_BOB),
        TRF_A_EXEC: _transfer(TRF_A_EXEC, ORG_A, ACC_A2, "executed", 12000, U_BOB),
        TRF_B1: _transfer(TRF_B1, ORG_B, ACC_B1, "draft", 4000, U_MALLORY),
    }
    beneficiaries = {
        BEN_A1: {"id": BEN_A1, "org_id": ORG_A, "name": "Initech LLC", "iban": "US99INITECH01",
                 "account_id": ACC_A1},
        BEN_B1: {"id": BEN_B1, "org_id": ORG_B, "name": "Staples Inc", "iban": "US99STAPLES1",
                 "account_id": ACC_B1},
    }
    cards = {
        CARD_A1: {"id": CARD_A1, "org_id": ORG_A, "account_id": ACC_A1, "holder": "Alice Admin",
                  "last4": "4242", "pan": "4242424242424242", "frozen": False, "spend_limit": 50000},
        CARD_B1: {"id": CARD_B1, "org_id": ORG_B, "account_id": ACC_B1, "holder": "Mallory Admin",
                  "last4": "1111", "pan": "4111111111111111", "frozen": False, "spend_limit": 10000},
    }
    statements = {
        STM_A1: {"id": STM_A1, "org_id": ORG_A, "account_id": ACC_A1, "period": "2026-05",
                 "opening": 4900000, "closing": 4820000, "lines": 142},
    }
    documents = {
        DOC_A1: {"id": DOC_A1, "org_id": ORG_A, "title": "Acme Q2 board deck",
                 "content": "CONFIDENTIAL: Acme acquisition targets and valuations."},
    }
    # A grant that ONCE let Org B view DOC_A1 but has expired.
    grants = {
        GRANT_B: {"id": GRANT_B, "document_id": DOC_A1, "grantee_org": ORG_B,
                  "expires_at": "2026-01-01T00:00:00Z", "active": True},
    }
    webhooks = {
        WH_A1: {"id": WH_A1, "org_id": ORG_A, "url": "https://hooks.acme.test/in", "secret": "whsec_acme"},
    }
    return {"orgs": orgs, "users": users, "accounts": accounts, "transactions": transactions,
            "receipts": receipts, "transfers": transfers, "beneficiaries": beneficiaries,
            "cards": cards, "statements": statements, "documents": documents, "grants": grants,
            "webhooks": webhooks, "exports": {}, "tokens": {}}


def _transfer(tid: str, org: str, src: str, status: str, amount: int, creator: str) -> dict:
    """A transfer object with enough nested fields to make a one-field write a 'tiny diff'."""
    return {
        "id": tid, "org_id": org, "source_account_id": src, "status": status,
        "amount": amount, "currency": "USD", "reference": f"REF-{tid[-4:]}",
        "created_by": creator, "approved_by": None, "destination_iban": "US99INITECH01",
        "schedule": {"when": "immediate", "tz": "UTC", "recurring": False, "interval_days": 0},
        "compliance": {"aml_score": 12, "sanctions_checked": True, "risk": "low", "reviewer": "system"},
        "audit": [{"at": "2026-05-01T00:00:00Z", "actor": creator, "action": "created"}],
        "fees": {"flat": 25, "fx": 0, "total": 25},
    }


DB = _seed()


def _require_user(authorization: Optional[str] = Header(default=None)) -> dict:
    """Resolve a bearer token to a user; 401 if missing/invalid. Applied to every route."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    uid = DB["tokens"].get(token)
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token")
    return DB["users"][uid]


def _get(coll: str, oid: str) -> dict:
    """Fetch an object or 404."""
    obj = DB[coll].get(oid)
    if not obj:
        raise HTTPException(status_code=404, detail="Not found")
    return obj


def _same_org(obj: dict, user: dict) -> None:
    """Enforce that the object belongs to the caller's org, else 403 (the correct check)."""
    if obj.get("org_id") != user["org_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")


def _account_org(account_id: str) -> Optional[str]:
    a = DB["accounts"].get(account_id)
    return a["org_id"] if a else None


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class Me(BaseModel):
    id: str
    org_id: str
    role: str
    email: str
    name: str


class StatusOk(BaseModel):
    status: str


class Org(BaseModel):
    id: str
    name: str
    tier: str


class OrgList(BaseModel):
    orgs: list[Org]


class Membership(BaseModel):
    id: str
    org_id: str
    role: str
    email: str
    name: str


class MembershipList(BaseModel):
    members: list[Membership]


class RoleUpdate(BaseModel):
    role: str


class AuditEntry(BaseModel):
    at: str
    actor: str
    action: str


class AuditLog(BaseModel):
    org_id: str
    entries: list[AuditEntry]


class Account(BaseModel):
    id: str
    org_id: str
    label: str
    currency: str
    balance: int
    frozen: bool
    daily_limit: int
    iban: str


class AccountList(BaseModel):
    accounts: list[Account]


class AccountCreate(BaseModel):
    label: str


class AccountExpanded(Account):
    transactions: Optional[list[dict]] = None


class LimitsUpdate(BaseModel):
    daily_limit: int


class Balance(BaseModel):
    account_id: str
    balance: int
    currency: str


class Transaction(BaseModel):
    id: str
    account_id: str
    amount: int
    memo: str
    beneficiary_id: str
    posted_at: str
    receipt_id: Optional[str] = None  # the receipt this transaction produced (the K1 chain producer)


class TransactionList(BaseModel):
    transactions: list[Transaction]


class Receipt(BaseModel):
    id: str
    transaction_id: str
    content: str


class Transfer(BaseModel):
    id: str
    org_id: str
    source_account_id: str
    status: str
    amount: int
    currency: str
    reference: str
    created_by: str
    approved_by: Optional[str]
    destination_iban: str
    schedule: dict
    compliance: dict
    audit: list[dict]
    fees: dict


class TransferList(BaseModel):
    transfers: list[Transfer]


class TransferCreate(BaseModel):
    source_account_id: str
    amount: int
    destination_iban: str


class TransferPatch(BaseModel):
    reference: Optional[str] = None


class BatchApprove(BaseModel):
    transfer_ids: list[str]


class CommitRequest(BaseModel):
    source_account_id: str


class Beneficiary(BaseModel):
    id: str
    org_id: str
    name: str
    iban: str
    account_id: str


class BeneficiaryList(BaseModel):
    beneficiaries: list[Beneficiary]


class Card(BaseModel):
    id: str
    org_id: str
    account_id: str
    holder: str
    last4: str
    frozen: bool
    spend_limit: int


class CardList(BaseModel):
    cards: list[Card]


class CardLimit(BaseModel):
    spend_limit: int


class Pan(BaseModel):
    card_id: str
    pan: str


class Statement(BaseModel):
    id: str
    org_id: str
    account_id: str
    period: str
    opening: int
    closing: int
    lines: int


class Document(BaseModel):
    id: str
    org_id: str
    title: str
    content: str


class DocumentSummary(BaseModel):
    id: str
    title: str


class DocumentList(BaseModel):
    documents: list[DocumentSummary]


class CashflowRow(BaseModel):
    account_id: str
    inflow: int
    outflow: int


class CashflowReport(BaseModel):
    org_id: str
    rows: list[CashflowRow]


class ExportCreate(BaseModel):
    resource: str
    org_id: Optional[str] = None  # honored without authorization check (K15)


class Export(BaseModel):
    id: str
    resource: str
    org_id: str
    status: str


class ExportData(BaseModel):
    id: str
    rows: list[dict]


class Webhook(BaseModel):
    id: str
    org_id: str
    url: str
    secret: str


class WebhookList(BaseModel):
    webhooks: list[Webhook]


class WebhookCreate(BaseModel):
    url: str


@app.post("/api/login", response_model=LoginResponse, tags=["auth"])
def login(body: LoginRequest):
    """Exchange email and password for a bearer token."""
    for u in DB["users"].values():
        if u["email"] == body.email and u["password"] == body.password:
            tok = uuid.uuid4().hex
            DB["tokens"][tok] = u["id"]
            return LoginResponse(access_token=tok)
    raise HTTPException(status_code=401, detail="Bad credentials")


@app.post("/api/logout", response_model=StatusOk, tags=["auth"])
def logout(user: dict = Depends(_require_user)):
    """End the current session."""
    return StatusOk(status="ok")


@app.get("/api/me", response_model=Me, tags=["auth"])
def me(user: dict = Depends(_require_user)):
    """Return the authenticated user."""
    return Me(**{k: user[k] for k in ("id", "org_id", "role", "email", "name")})


@app.get("/api/orgs", response_model=OrgList, tags=["orgs"])
def list_orgs(user: dict = Depends(_require_user)):
    """List organizations the caller belongs to."""
    return OrgList(orgs=[Org(**DB["orgs"][user["org_id"]])])


@app.get("/api/orgs/{org_id}", response_model=Org, tags=["orgs"])
def get_org(org_id: str, user: dict = Depends(_require_user)):
    """Return an organization."""
    org = _get("orgs", org_id)
    if org_id != user["org_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return Org(**org)


@app.patch("/api/orgs/{org_id}", response_model=Org, tags=["orgs"])
def update_org(org_id: str, body: dict, user: dict = Depends(_require_user)):
    """Update an organization's profile."""
    org = _get("orgs", org_id)
    if org_id != user["org_id"] or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    if "name" in body:
        org["name"] = body["name"]
    return Org(**org)


@app.get("/api/orgs/{org_id}/members", response_model=MembershipList, tags=["orgs"])
def list_members(org_id: str, user: dict = Depends(_require_user)):
    """List the members of an organization."""
    if org_id != user["org_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    members = [Membership(id=u["id"], org_id=u["org_id"], role=u["role"], email=u["email"], name=u["name"])
               for u in DB["users"].values() if u["org_id"] == org_id]
    return MembershipList(members=members)


@app.get("/api/orgs/{org_id}/audit-log", response_model=AuditLog, tags=["orgs"])
def org_audit_log(org_id: str, user: dict = Depends(_require_user)):
    """Return an organization's audit log."""
    if org_id != user["org_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return AuditLog(org_id=org_id, entries=[AuditEntry(at="2026-05-01T00:00:00Z", actor=user["id"], action="login")])


@app.get("/api/memberships", response_model=MembershipList, tags=["memberships"])
def my_memberships(user: dict = Depends(_require_user)):
    """List the caller's own memberships."""
    return MembershipList(members=[Membership(id=user["id"], org_id=user["org_id"], role=user["role"],
                                              email=user["email"], name=user["name"])])


@app.patch("/api/memberships/{user_id}/role", response_model=Membership, tags=["memberships"])
def update_role(user_id: str, body: RoleUpdate, user: dict = Depends(_require_user)):
    """Change a member's role."""
    target = _get("users", user_id)
    if target["org_id"] != user["org_id"] or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    target["role"] = body.role
    return Membership(id=target["id"], org_id=target["org_id"], role=target["role"],
                      email=target["email"], name=target["name"])


@app.delete("/api/memberships/{user_id}", response_model=StatusOk, tags=["memberships"])
def remove_member(user_id: str, user: dict = Depends(_require_user)):
    """Remove a member from the organization."""
    target = _get("users", user_id)
    if target["org_id"] != user["org_id"] or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return StatusOk(status="removed")


@app.get("/api/accounts", response_model=AccountList, tags=["accounts"])
def list_accounts(user: dict = Depends(_require_user)):
    """List the caller's organization accounts."""
    return AccountList(accounts=[Account(**a) for a in DB["accounts"].values() if a["org_id"] == user["org_id"]])


@app.post("/api/accounts", response_model=Account, tags=["accounts"])
def create_account(body: AccountCreate, user: dict = Depends(_require_user)):
    """Open a new account in the caller's organization."""
    aid = str(uuid.uuid4())
    acc = {"id": aid, "org_id": user["org_id"], "label": body.label, "currency": "USD",
           "balance": 0, "frozen": False, "daily_limit": 50000, "iban": f"US00NEW{aid[:6]}"}
    DB["accounts"][aid] = acc
    return Account(**acc)


@app.get("/api/accounts/{account_id}", response_model=AccountExpanded, tags=["accounts"])
def get_account(account_id: str, expand: Optional[str] = Query(default=None),
                user: dict = Depends(_require_user)):
    """Return an account, optionally expanding related collections."""
    acc = _get("accounts", account_id)
    if expand:
        # KEY:K12 — the expand path returns data before the ownership check runs.
        txns = [t for t in DB["transactions"].values() if t["account_id"] == account_id] if "transactions" in expand else None
        return AccountExpanded(**acc, transactions=txns)
    _same_org(acc, user)
    return AccountExpanded(**acc)


@app.patch("/api/accounts/{account_id}", response_model=Account, tags=["accounts"])
async def update_account(account_id: str, request: Request, user: dict = Depends(_require_user)):
    """Update an account's profile."""
    acc = _get("accounts", account_id)
    _same_org(acc, user)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if "label" in body:
        acc["label"] = body["label"]
    # KEY:MA1 — org_id is accepted from the body and moves the account to another org.
    if "org_id" in body and body["org_id"] in DB["orgs"]:
        acc["org_id"] = body["org_id"]
    return Account(**acc)


@app.delete("/api/accounts/{account_id}", response_model=StatusOk, tags=["accounts"])
def delete_account(account_id: str, user: dict = Depends(_require_user)):
    """Close an account."""
    acc = _get("accounts", account_id)
    _same_org(acc, user)
    del DB["accounts"][account_id]
    return StatusOk(status="closed")


@app.get("/api/accounts/{account_id}/balance", response_model=Balance, tags=["accounts"])
def account_balance(account_id: str, user: dict = Depends(_require_user)):
    """Return an account's balance."""
    acc = _get("accounts", account_id)
    _same_org(acc, user)
    return Balance(account_id=account_id, balance=acc["balance"], currency=acc["currency"])


@app.patch("/api/accounts/{account_id}/limits", response_model=StatusOk, tags=["accounts"])
def update_limits(account_id: str, body: LimitsUpdate, user: dict = Depends(_require_user)):
    """Update an account's transaction limits."""
    acc = DB["accounts"].get(account_id)
    # KEY:K7 — silent write: applies regardless of org, always returns the same 200 body.
    if acc:
        acc["daily_limit"] = body.daily_limit
    return StatusOk(status="ok")


@app.post("/api/accounts/{account_id}/freeze", response_model=StatusOk, tags=["accounts"])
def freeze_account(account_id: str, user: dict = Depends(_require_user)):
    """Freeze an account."""
    acc = _get("accounts", account_id)
    # KEY:K6 — forbidden-but-done: the mutation is applied before the guard returns 403.
    acc["frozen"] = True
    if acc["org_id"] != user["org_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return StatusOk(status="frozen")


@app.post("/api/accounts/{account_id}/unfreeze", response_model=StatusOk, tags=["accounts"])
def unfreeze_account(account_id: str, user: dict = Depends(_require_user)):
    """Unfreeze an account."""
    acc = _get("accounts", account_id)
    _same_org(acc, user)
    acc["frozen"] = False
    return StatusOk(status="active")


@app.get("/api/accounts/{account_id}/transactions", response_model=TransactionList, tags=["accounts"])
def account_transactions(account_id: str, user: dict = Depends(_require_user)):
    """List an account's transactions."""
    _get("accounts", account_id)
    # KEY:K3 — no org check (the sibling GET /accounts/{id} is correctly checked).
    txns = [Transaction(**t) for t in DB["transactions"].values() if t["account_id"] == account_id]
    return TransactionList(transactions=txns)


@app.get("/api/accounts/{account_id}/transactions/{txn_id}/receipts/{receipt_id}",
         response_model=Receipt, tags=["accounts"])
def get_receipt(account_id: str, txn_id: str, receipt_id: str, user: dict = Depends(_require_user)):
    """Return a transaction receipt."""
    rcp = _get("receipts", receipt_id)
    # KEY:K1 — deep 4-hop chain read, no org check anywhere on the path.
    return Receipt(**rcp)


@app.get("/api/accounts/{account_id}/statement", response_model=Statement, tags=["accounts"])
def account_statement(account_id: str, user: dict = Depends(_require_user)):
    """Return an account's latest statement."""
    acc = _get("accounts", account_id)
    _same_org(acc, user)
    stm = next((s for s in DB["statements"].values() if s["account_id"] == account_id), None)
    if not stm:
        raise HTTPException(status_code=404, detail="Not found")
    return Statement(**stm)


@app.get("/api/transactions", response_model=TransactionList, tags=["transactions"])
def search_transactions(beneficiary_id: Optional[str] = Query(default=None),
                        user: dict = Depends(_require_user)):
    """Search transactions by filter."""
    items = list(DB["transactions"].values())
    if beneficiary_id:
        # KEY:K11 — filter returns matching rows across all orgs (no org scoping).
        items = [t for t in items if t["beneficiary_id"] == beneficiary_id]
    else:
        own = {a["id"] for a in DB["accounts"].values() if a["org_id"] == user["org_id"]}
        items = [t for t in items if t["account_id"] in own]
    return TransactionList(transactions=[Transaction(**t) for t in items])


@app.get("/api/transactions/{txn_id}", response_model=Transaction, tags=["transactions"])
def get_transaction(txn_id: str, user: dict = Depends(_require_user)):
    """Return a single transaction."""
    txn = _get("transactions", txn_id)
    if _account_org(txn["account_id"]) != user["org_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return Transaction(**txn)


@app.get("/api/transfers", response_model=TransferList, tags=["transfers"])
def list_transfers(user: dict = Depends(_require_user)):
    """List the caller's organization transfers."""
    return TransferList(transfers=[Transfer(**t) for t in DB["transfers"].values() if t["org_id"] == user["org_id"]])


@app.post("/api/transfers", response_model=Transfer, tags=["transfers"])
async def create_transfer(request: Request, user: dict = Depends(_require_user)):
    """Create a draft transfer."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    org = user["org_id"]
    tid = str(uuid.uuid4())
    trf = _transfer(tid, org, body.get("source_account_id", ACC_A1), "draft",
                    int(body.get("amount", 0)), user["id"])
    trf["destination_iban"] = body.get("destination_iban", "US00UNKNOWN")
    DB["transfers"][tid] = trf
    return Transfer(**trf)


@app.get("/api/transfers/{transfer_id}", response_model=Transfer, tags=["transfers"])
def get_transfer(transfer_id: str, user: dict = Depends(_require_user)):
    """Return a transfer."""
    trf = _get("transfers", transfer_id)
    _same_org(trf, user)
    return Transfer(**trf)


@app.patch("/api/transfers/{transfer_id}", response_model=Transfer, tags=["transfers"])
def patch_transfer(transfer_id: str, body: TransferPatch, user: dict = Depends(_require_user)):
    """Update a draft transfer's reference."""
    trf = _get("transfers", transfer_id)
    # KEY:K8 — tiny diff: one field changes, whole large object echoed; no org check.
    if body.reference is not None:
        trf["reference"] = body.reference
    return Transfer(**trf)


@app.delete("/api/transfers/{transfer_id}", response_model=StatusOk, tags=["transfers"])
def delete_transfer(transfer_id: str, user: dict = Depends(_require_user)):
    """Delete a draft transfer."""
    trf = _get("transfers", transfer_id)
    _same_org(trf, user)
    del DB["transfers"][transfer_id]
    return StatusOk(status="deleted")


@app.post("/api/transfers/{transfer_id}/submit", response_model=Transfer, tags=["transfers"])
def submit_transfer(transfer_id: str, user: dict = Depends(_require_user)):
    """Submit a draft transfer for approval."""
    trf = _get("transfers", transfer_id)
    _same_org(trf, user)
    trf["status"] = "pending_approval"
    return Transfer(**trf)


@app.post("/api/transfers/{transfer_id}/approve", response_model=Transfer, tags=["transfers"])
def approve_transfer(transfer_id: str, user: dict = Depends(_require_user)):
    """Approve a pending transfer."""
    trf = _get("transfers", transfer_id)
    # KEY:K13 — approval only checks that the transfer is pending, not that the caller shares its org.
    if trf["created_by"] == user["id"]:
        raise HTTPException(status_code=403, detail="Creator cannot approve")
    if trf["status"] != "pending_approval":
        raise HTTPException(status_code=409, detail="Not pending")
    trf["status"] = "approved"
    trf["approved_by"] = user["id"]
    return Transfer(**trf)


@app.post("/api/transfers/{transfer_id}/reject", response_model=Transfer, tags=["transfers"])
def reject_transfer(transfer_id: str, user: dict = Depends(_require_user)):
    """Reject a pending transfer."""
    trf = _get("transfers", transfer_id)
    _same_org(trf, user)
    trf["status"] = "rejected"
    return Transfer(**trf)


@app.post("/api/transfers/{transfer_id}/cancel", response_model=Transfer, tags=["transfers"])
def cancel_transfer(transfer_id: str, user: dict = Depends(_require_user)):
    """Cancel a transfer."""
    trf = _get("transfers", transfer_id)
    _same_org(trf, user)
    trf["status"] = "cancelled"
    return Transfer(**trf)


@app.post("/api/transfers/{transfer_id}/commit", response_model=Transfer, tags=["transfers"])
def commit_transfer(transfer_id: str, body: CommitRequest, user: dict = Depends(_require_user)):
    """Finalize an approved transfer against a confirmed source account."""
    trf = _get("transfers", transfer_id)
    _same_org(trf, user)
    # KEY:K16 — TOCTOU: the source account supplied at commit time is NOT re-checked for org.
    trf["source_account_id"] = body.source_account_id
    trf["status"] = "executed"
    return Transfer(**trf)


@app.post("/api/transfers/batch", response_model=TransferList, tags=["transfers"])
def batch_approve(body: BatchApprove, user: dict = Depends(_require_user)):
    """Approve several pending transfers at once."""
    ids = body.transfer_ids
    if not ids:
        return TransferList(transfers=[])
    first = DB["transfers"].get(ids[0])
    # KEY:K14 — only the first transfer's org is checked; the rest are processed unchecked.
    if first and first["org_id"] != user["org_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    out = []
    for tid in ids:
        t = DB["transfers"].get(tid)
        if t and t["status"] == "pending_approval":
            t["status"] = "approved"
            t["approved_by"] = user["id"]
            out.append(Transfer(**t))
    return TransferList(transfers=out)


@app.get("/api/beneficiaries", response_model=BeneficiaryList, tags=["beneficiaries"])
def list_beneficiaries(user: dict = Depends(_require_user)):
    """List the caller's organization beneficiaries."""
    return BeneficiaryList(beneficiaries=[Beneficiary(**b) for b in DB["beneficiaries"].values()
                                          if b["org_id"] == user["org_id"]])


@app.post("/api/beneficiaries", response_model=Beneficiary, tags=["beneficiaries"])
def create_beneficiary(body: dict, user: dict = Depends(_require_user)):
    """Add a beneficiary to the caller's organization."""
    bid = str(uuid.uuid4())
    ben = {"id": bid, "org_id": user["org_id"], "name": body.get("name", "Unnamed"),
           "iban": body.get("iban", "US00NEW"), "account_id": body.get("account_id", "")}
    DB["beneficiaries"][bid] = ben
    return Beneficiary(**ben)


@app.get("/api/beneficiaries/{beneficiary_id}", response_model=Beneficiary, tags=["beneficiaries"])
def get_beneficiary(beneficiary_id: str, user: dict = Depends(_require_user)):
    """Return a beneficiary."""
    ben = _get("beneficiaries", beneficiary_id)
    # KEY:K5 — no org check.
    return Beneficiary(**ben)


@app.delete("/api/beneficiaries/{beneficiary_id}", response_model=StatusOk, tags=["beneficiaries"])
def delete_beneficiary(beneficiary_id: str, user: dict = Depends(_require_user)):
    """Remove a beneficiary."""
    ben = _get("beneficiaries", beneficiary_id)
    _same_org(ben, user)
    del DB["beneficiaries"][beneficiary_id]
    return StatusOk(status="deleted")


@app.get("/api/cards", response_model=CardList, tags=["cards"])
def list_cards(user: dict = Depends(_require_user)):
    """List the caller's organization cards."""
    return CardList(cards=[Card(**{k: c[k] for k in ("id", "org_id", "account_id", "holder", "last4", "frozen", "spend_limit")})
                           for c in DB["cards"].values() if c["org_id"] == user["org_id"]])


@app.get("/api/cards/{card_id}", response_model=Card, tags=["cards"])
def get_card(card_id: str, user: dict = Depends(_require_user)):
    """Return a card."""
    card = _get("cards", card_id)
    _same_org(card, user)
    return Card(**{k: card[k] for k in ("id", "org_id", "account_id", "holder", "last4", "frozen", "spend_limit")})


@app.post("/api/cards/{card_id}/reveal", response_model=Pan, tags=["cards"])
def reveal_pan(card_id: str, user: dict = Depends(_require_user)):
    """Reveal a card's full number."""
    card = _get("cards", card_id)
    # KEY:K2 — cross-org PAN disclosure, no org check.
    return Pan(card_id=card_id, pan=card["pan"])


@app.post("/api/cards/{card_id}/freeze", response_model=StatusOk, tags=["cards"])
def freeze_card(card_id: str, user: dict = Depends(_require_user)):
    """Freeze a card."""
    card = DB["cards"].get(card_id)
    # KEY:K9 — silent cross-org write: applies to any card, generic 200.
    if card:
        card["frozen"] = True
    return StatusOk(status="frozen")


@app.patch("/api/cards/{card_id}/limit", response_model=Card, tags=["cards"])
def update_card_limit(card_id: str, body: CardLimit, user: dict = Depends(_require_user)):
    """Update a card's spend limit."""
    card = _get("cards", card_id)
    _same_org(card, user)
    card["spend_limit"] = body.spend_limit
    return Card(**{k: card[k] for k in ("id", "org_id", "account_id", "holder", "last4", "frozen", "spend_limit")})


@app.delete("/api/cards/{card_id}", response_model=StatusOk, tags=["cards"])
def delete_card(card_id: str, user: dict = Depends(_require_user)):
    """Cancel a card."""
    card = _get("cards", card_id)
    _same_org(card, user)
    del DB["cards"][card_id]
    return StatusOk(status="cancelled")


@app.get("/api/statements/{statement_id}", response_model=Statement, tags=["statements"])
def get_statement(statement_id: str, user: dict = Depends(_require_user)):
    """Return a statement."""
    stm = _get("statements", statement_id)
    _same_org(stm, user)
    return Statement(**stm)


@app.get("/api/documents", response_model=DocumentList, tags=["documents"])
def list_documents(user: dict = Depends(_require_user)):
    """List the caller's organization documents."""
    docs = [{"id": d["id"], "title": d["title"]} for d in DB["documents"].values() if d["org_id"] == user["org_id"]]
    return DocumentList(documents=docs)


@app.get("/api/documents/{document_id}", response_model=Document, tags=["documents"])
def get_document(document_id: str, user: dict = Depends(_require_user)):
    """Return a document, honoring any access grant."""
    doc = _get("documents", document_id)
    if doc["org_id"] == user["org_id"]:
        return Document(**doc)
    # KEY:K4 — a grant is honored without checking its expiry/active window.
    for g in DB["grants"].values():
        if g["document_id"] == document_id and g["grantee_org"] == user["org_id"] and g["active"]:
            return Document(**doc)
    raise HTTPException(status_code=403, detail="Forbidden")


@app.delete("/api/documents/{document_id}", response_model=StatusOk, tags=["documents"])
def delete_document(document_id: str, user: dict = Depends(_require_user)):
    """Delete a document."""
    doc = _get("documents", document_id)
    _same_org(doc, user)
    del DB["documents"][document_id]
    return StatusOk(status="deleted")


@app.get("/api/reports/cashflow", response_model=CashflowReport, tags=["reports"])
def cashflow(org_id: Optional[str] = Query(default=None), user: dict = Depends(_require_user)):
    """Return a cashflow report for an organization."""
    target = org_id or user["org_id"]
    # KEY:K10 — the supplied org_id is used without checking it is the caller's own.
    accs = [a for a in DB["accounts"].values() if a["org_id"] == target]
    rows = [CashflowRow(account_id=a["id"], inflow=max(a["balance"], 0), outflow=a["daily_limit"]) for a in accs]
    return CashflowReport(org_id=target, rows=rows)


@app.post("/api/exports", response_model=Export, tags=["reports"])
def create_export(body: ExportCreate, user: dict = Depends(_require_user)):
    """Create an export job."""
    eid = str(uuid.uuid4())
    # KEY:K15 — org_id from the body is honored without authorization; artifact fetched later.
    target = body.org_id or user["org_id"]
    DB["exports"][eid] = {"id": eid, "resource": body.resource, "org_id": target,
                          "status": "ready", "owner": user["id"]}
    return Export(id=eid, resource=body.resource, org_id=target, status="ready")


@app.get("/api/exports/{export_id}", response_model=Export, tags=["reports"])
def get_export(export_id: str, user: dict = Depends(_require_user)):
    """Return an export job's status."""
    e = _get("exports", export_id)
    if e["owner"] != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return Export(id=e["id"], resource=e["resource"], org_id=e["org_id"], status=e["status"])


@app.get("/api/exports/{export_id}/download", response_model=ExportData, tags=["reports"])
def download_export(export_id: str, user: dict = Depends(_require_user)):
    """Download an export artifact."""
    e = _get("exports", export_id)
    if e["owner"] != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    # KEY:K15 — artifact materializes whatever org the job captured, regardless of caller's org.
    if e["resource"] == "accounts":
        rows = [dict(a) for a in DB["accounts"].values() if a["org_id"] == e["org_id"]]
    else:
        rows = [dict(t) for t in DB["transactions"].values()
                if _account_org(t["account_id"]) == e["org_id"]]
    return ExportData(id=export_id, rows=rows)


@app.get("/api/webhooks", response_model=WebhookList, tags=["webhooks"])
def list_webhooks(user: dict = Depends(_require_user)):
    """List the caller's organization webhooks."""
    return WebhookList(webhooks=[Webhook(**w) for w in DB["webhooks"].values() if w["org_id"] == user["org_id"]])


@app.post("/api/webhooks", response_model=Webhook, tags=["webhooks"])
def create_webhook(body: WebhookCreate, user: dict = Depends(_require_user)):
    """Register a webhook for the caller's organization."""
    wid = str(uuid.uuid4())
    wh = {"id": wid, "org_id": user["org_id"], "url": body.url, "secret": f"whsec_{wid[:8]}"}
    DB["webhooks"][wid] = wh
    return Webhook(**wh)


@app.get("/api/webhooks/{webhook_id}", response_model=Webhook, tags=["webhooks"])
def get_webhook(webhook_id: str, user: dict = Depends(_require_user)):
    """Return a webhook."""
    wh = _get("webhooks", webhook_id)
    _same_org(wh, user)
    return Webhook(**wh)


@app.delete("/api/webhooks/{webhook_id}", response_model=StatusOk, tags=["webhooks"])
def delete_webhook(webhook_id: str, user: dict = Depends(_require_user)):
    """Delete a webhook."""
    wh = _get("webhooks", webhook_id)
    _same_org(wh, user)
    del DB["webhooks"][webhook_id]
    return StatusOk(status="deleted")


@app.post("/api/admin/reset", response_model=StatusOk, tags=["admin"], include_in_schema=False)
def reset():
    """Reseed the in-memory world (operator-only, hidden from the spec)."""
    global DB
    DB = _seed()
    return StatusOk(status="reset")
