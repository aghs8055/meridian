# Answer key

This file lists every vulnerability embedded in Meridian. **Do not give it to a tool under test.**
Each vulnerability is also marked in `app.py` with a `# KEY:` comment, and `selftest.py` checks
that all of them can be exploited and that the secured decoys cannot.

Unless stated otherwise, the victim is **alice** (Org A) and the attacker is **mallory** (Org B).
All paths start with `/api`.

## BOLA vulnerabilities

### Unauthorized reads

| Key | Endpoint | What goes wrong |
|---|---|---|
| K1 | `GET /accounts/{account_id}/transactions/{txn_id}/receipts/{receipt_id}` | No organization check anywhere on a four-level path. |
| K2 | `POST /cards/{card_id}/reveal` | Reveals the full card number of any card. |
| K3 | `GET /accounts/{account_id}/transactions` | No organization check, while the sibling `GET /accounts/{account_id}` is secured. |
| K4 | `GET /documents/{document_id}` | An access grant is honored after it has expired. |
| K5 | `GET /beneficiaries/{beneficiary_id}` | No organization check. |

### Unauthorized writes

| Key | Endpoint | What goes wrong |
|---|---|---|
| K6 | `POST /accounts/{account_id}/freeze` | Returns 403, but the account is frozen anyway. |
| K7 | `PATCH /accounts/{account_id}/limits` | Applies to any account and always returns the same 200 response. |
| K8 | `PATCH /transfers/{transfer_id}` | No organization check; one field changes in a large object. |
| K9 | `POST /cards/{card_id}/freeze` | Applies to any card and returns a generic 200 response. |

### Leaks through filters and query options

| Key | Endpoint | What goes wrong |
|---|---|---|
| K10 | `GET /reports/cashflow?org_id=` | The `org_id` parameter is used without checking that it is the caller's organization. |
| K11 | `GET /transactions?beneficiary_id=` | The filter returns matching rows from all organizations. |
| K12 | `GET /accounts/{account_id}?expand=transactions` | With `expand`, data is returned before the organization check runs; the plain request returns 403. |

### State-dependent, multi-step and asynchronous

| Key | Endpoint | What goes wrong |
|---|---|---|
| K13 | `POST /transfers/{transfer_id}/approve` | A pending transfer of another organization can be approved. |
| K14 | `POST /transfers/batch` | Only the first transfer in the batch is checked. |
| K15 | `POST /exports` → `GET /exports/{export_id}/download` | The `org_id` in the request body is honored; the leaked data is fetched later from the export. |
| K16 | `POST /transfers/{transfer_id}/commit` | The source account given at commit time is not checked. |

## Other weaknesses (not BOLA)

| Key | Endpoint | What goes wrong |
|---|---|---|
| MA1 | `PATCH /accounts/{account_id}` | Mass assignment: a member of the account's organization can move it to another organization through `org_id` in the body. |

## Secured decoys

These endpoints look similar to the vulnerable ones but correctly reject the attacker. A precise
tool must **not** report them.

- `GET` and `DELETE /accounts/{account_id}`, `/accounts/{account_id}/balance`,
  `/accounts/{account_id}/statement`, `/accounts/{account_id}/unfreeze`
- `GET` and `DELETE /transfers/{transfer_id}`, `/transfers/{transfer_id}/reject`,
  `/transfers/{transfer_id}/cancel`, `/transfers/{transfer_id}/submit`
- `GET /transactions/{txn_id}`, `GET /statements/{statement_id}`
- `GET` and `DELETE /cards/{card_id}`, `PATCH /cards/{card_id}/limit`
- `DELETE /documents/{document_id}`, `DELETE /beneficiaries/{beneficiary_id}`
- `GET` and `PATCH /orgs/{org_id}`, `/orgs/{org_id}/members`, `/orgs/{org_id}/audit-log`
- `PATCH /memberships/{user_id}/role`, `DELETE /memberships/{user_id}`
- `GET` and `DELETE /webhooks/{webhook_id}`

## Seeded objects

| Kind | Org A (victim) | Org B (attacker) |
|---|---|---|
| Organization | `org-acme-1111` | `org-zenith-2222` |
| Users | alice (admin), bob (initiator), carol (approver) | mallory (admin) |
| Accounts | `ACC_A1`, `ACC_A2` | `ACC_B1` |
| Transfers | `TRF_A_DRAFT`, `TRF_A_PEND`, `TRF_A_EXEC` | `TRF_B1` |
| Other | `TXN_A1`, `RCP_A1`, `BEN_A1`, `CARD_A1`, `STM_A1`, `DOC_A1` (with expired grant `GRANT_B`) | |

The exact ID values are defined at the top of `app.py`.
