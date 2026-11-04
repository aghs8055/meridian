# Meridian

Meridian is a small, intentionally vulnerable REST API for evaluating tools that detect
**Broken Object Level Authorization (BOLA)**. It models a multi-organization treasury and payments
platform with accounts, transactions, transfers with an approval workflow, beneficiaries, cards,
statements, documents, reports, exports and webhooks.

It has:

- **58 API operations**, described by a complete OpenAPI specification (`openapi.json`);
- **16 BOLA vulnerabilities** of different kinds, from simple missing checks to writes that return
  an error but are applied anyway, leaks through filters, and multi-step attacks;
- **secured decoys**, endpoints that look like the vulnerable ones but are correctly protected, so
  that false positives can be measured;
- an **answer key** (`ANSWER_KEY.md`) and a **self-test** (`selftest.py`) that proves the answer
  key is accurate.

Meridian was built for the evaluation of Parallax, a semi-automated BOLA detection tool.

> **Warning:** Meridian is insecure by design. Run it only on your own machine and never expose
> it to a network.

## Quick start

Requires Python 3.10 or later.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8005
```

The API is then available at `http://127.0.0.1:8005`, and its specification at
`http://127.0.0.1:8005/openapi.json` (the same file as `openapi.json` in this repository).

All data is kept in memory. Restarting the server, or calling the reset endpoint, restores the
initial data, so every run starts from the same state:

```bash
curl -X POST http://127.0.0.1:8005/api/admin/reset
```

The reset endpoint is not part of the specification, so a tool under test does not see it.

## Users

All users have the password `Passw0rd!`.

| User | Organization | Role | Typical use |
|---|---|---|---|
| `alice@acme.test` | Org A (Acme Capital) | admin | victim |
| `mallory@zenith.test` | Org B (Zenith Holdings) | admin | attacker |
| `bob@acme.test` | Org A | initiator | |
| `carol@acme.test` | Org A | approver | |

Log in with `POST /api/login` and a JSON body `{"email": "...", "password": "..."}`. The response
contains an `access_token`, which is sent in later requests as `Authorization: Bearer <token>`.

## Evaluating a tool

1. Start Meridian and reset it.
2. Give the tool the specification and the credentials of the victim (alice) and the attacker
   (mallory). If the tool accepts a description of the access rules, you can use:

   > Multi-organization treasury/payments platform. Authenticated members belong to one
   > organization and manage that org's accounts, transactions, transfers (with an approval
   > workflow), beneficiaries, cards, statements, documents, reports, exports and webhooks.
   > Members must only access their own organization's objects. Object ids are opaque strings.

3. Compare the reported findings with `ANSWER_KEY.md`. A reported secured decoy is a false
   positive.

## Checking the answer key

```bash
python selftest.py
```

The self-test runs every attack in the answer key, checks that every secured decoy rejects the
attacker, and searches all other endpoints for cross-organization reads and writes that the
answer key does not list. It ends with a summary and exits with status 1 if anything fails:

```
SUMMARY: 16/16 keyed fire, 0 leaky decoys, 0 unexpected vulns
```

## Files

| File | Content |
|---|---|
| `app.py` | The API (FastAPI). Each vulnerability is marked with a `# KEY:` comment. |
| `openapi.json` | The OpenAPI specification generated from `app.py`. |
| `ANSWER_KEY.md` | All vulnerabilities, secured decoys and seeded objects. |
| `selftest.py` | Checks that the answer key is accurate. |
| `requirements.txt` | Python dependencies. |

To regenerate `openapi.json` after changing `app.py`:

```bash
python -c "import json, app; json.dump(app.app.openapi(), open('openapi.json', 'w'), indent=2)"
```

## License

MIT, see [LICENSE](LICENSE).
