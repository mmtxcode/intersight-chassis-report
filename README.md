# Intersight Chassis Inventory Report

A small Python script that queries the Cisco Intersight API and produces a chassis slot-utilization report — chassis Name, Model, Serial, and slots Total / Used / Available — sorted with the most-available chassis on top so you can see at a glance where new blades can land.

Output formats: **CSV** or **PDF**.

## Requirements

- Python 3.9+
- A Cisco Intersight account with an **API Key Version 3** (ECDSA P-256). A read-only role is sufficient.

## Setup

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate           # macOS/Linux
# .venv\Scripts\activate            # Windows PowerShell

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create .env from the template and fill it in
cp .env.example .env
```

### Generating the API key in Intersight

1. **Settings → API Keys → Generate API Key**
2. Choose **API Key Version 3**.
3. Pick a role with at least Read-Only privileges (the role must permit reads on `equipment.Chassis` and `compute.Blade`).
4. Save the **API Key ID** into `INTERSIGHT_API_KEY_ID` in `.env`.
5. Download the `.pem` file and put its path into `INTERSIGHT_API_KEY_FILE`.

## Usage

```bash
# CSV to a file
python chassis_report.py --format csv -o chassis.csv

# CSV to stdout (pipe-friendly)
python chassis_report.py --format csv

# PDF
python chassis_report.py --format pdf -o chassis.pdf

# Verbose: log each request URL (signature redacted)
python chassis_report.py --format csv -o chassis.csv --debug
```

The report title is auto-populated as **"Chassis Inventory for &lt;Account Name&gt;"** by reading `/api/v1/iam/Accounts/<account_moid>`. If your API key role can't read that endpoint, set `INTERSIGHT_ACCOUNT_NAME` in `.env` and that value is used instead.

## Slot capacity per model

The script needs to know each chassis model's total slot count. Two sources, in order:

1. **`KNOWN_CAPACITY` table** at the top of `chassis_report.py`. Add an entry when a new model appears in your fleet.
2. **Observed-max heuristic.** For models not in the table, the script uses the highest `SlotId` seen across all blades of that model in your fleet. This is a lower bound: a sparsely populated model can under-report.

The current table:

```python
KNOWN_CAPACITY = {
    "UCSX-9508":     8,
    "UCSB-5108-AC2": 8,  # 8 half-width slots (or 4 full-width)
}
```

If a chassis returns `?` in the Total/Available columns, it's a model the table doesn't know about and no fleet blade has been observed in any slot. Either populate a blade in it once, or add the model to `KNOWN_CAPACITY`.

## Notes — things that took me longer than they should have

A few quirks worth knowing if you build similar tooling:

- **The collection URL for `equipment.Chassis` is `/api/v1/equipment/Chasses`**, not `/api/v1/equipment/Chassis`. The MO type name is singular but the URL plural is irregular. Hitting the singular path returns `403 InvalidUrl / iam_invalid_method_operation`, which is misleading — it sounds like a permission problem but is purely a URL issue.
- **HTTP Signature: ECDSA must be DER-encoded**, not raw `r‖s` (IEEE P1363) — even though the literal hs2019 spec calls for raw. Intersight's verifier rejects raw with `iam_api_key_is_invalid` (401).
- **`Content-Type: application/json` must be in the signed-headers list** even on GETs with no body. Cisco's docs example includes it.
- **`/api/v1/iam/Accounts/<moid>` direct GET often succeeds** for non-admin keys even though listing `/api/v1/iam/Accounts` is denied — different permission semantics for read-by-Moid vs list.

## Project layout

```
.
├── chassis_report.py     # main script
├── requirements.txt
├── .env.example          # copy to .env and fill in
├── .gitignore            # excludes .env, *.pem, *.csv, *.pdf, venv/
└── README.md
```

## What's NOT in this repo

By design, the following are gitignored and never committed:

- `.env` (your API key ID and any other secrets)
- `*.pem` (your private key file)
- `*.csv`, `*.pdf` (any reports you generate — these contain real chassis identifiers)
- `.venv/`, `__pycache__/`
