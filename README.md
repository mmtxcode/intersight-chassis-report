# Intersight Chassis Inventory Report

A Python tool that queries the Cisco Intersight API and produces a chassis slot-utilization report, sorted to surface the chassis with the most available capacity. Useful for capacity planning — answering *"where can I rack the next blade?"* — without manually walking the Intersight UI.

Output formats: CSV or PDF.

---

## Contents

1. [Overview](#overview)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [API key setup](#api-key-setup)
5. [Configuration](#configuration)
6. [Usage](#usage)
7. [Sample output](#sample-output)
8. [Required Intersight permissions](#required-intersight-permissions)
9. [Slot capacity configuration](#slot-capacity-configuration)
10. [How it works](#how-it-works)
11. [Project layout](#project-layout)

---

## Overview

The script:

- Authenticates to the Intersight REST API via Cavage HTTP Signatures using a v3 API key (ECDSA P-256).
- Pulls the chassis, blade, and PCIe-node inventory in three paginated calls.
- Joins them client-side: blades attach to chassis directly; PCIe Nodes attach via their X-Fabric-paired blade (a two-hop join, since `pci.Node` does not reference its chassis directly).
- Counts blades + PCIe Nodes as occupied slots and calculates total / used / available per chassis.
- Renders to CSV or PDF, sorted with the most-available chassis at the top.

The report title is auto-populated with the Intersight account display name (resolved by Moid from the API key ID).

---

## Requirements

| Item | Version / Notes |
| --- | --- |
| Python | 3.9 or newer |
| Cisco Intersight account | SaaS (`https://intersight.com`) or Virtual Appliance |
| API Key | Version 3 (ECDSA P-256). v2 RSA keys also work but are deprecated. |
| Role on the API key | At minimum, read access to `equipment.Chassis`, `compute.Blade`, and `pci.Node`. The built-in **Read-Only** role covers all three. |

Python dependencies (installed via `requirements.txt`):

- `requests` — HTTP client
- `cryptography` — ECDSA / RSA signing for HTTP Signatures
- `python-dotenv` — `.env` loader
- `reportlab` — PDF rendering

---

## Installation

```bash
# 1. Clone or download the repo
git clone https://github.com/mmtxcode/intersight-chassis-report.git
cd intersight-chassis-report

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate           # macOS / Linux
# .venv\Scripts\activate            # Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize your local .env from the template
cp .env.example .env
```

---

## API key setup

1. In Intersight: **Settings → API Keys → Generate API Key**.
2. Set **API Key Version** to **v3**.
3. Assign a role that has read access to chassis, blades, and PCIe nodes (the built-in **Read-Only** role is sufficient).
4. Click **Generate**, then download the `.pem` private key file. Intersight only shows it once — save it before closing the dialog.
5. Copy the displayed **API Key ID** (format: `<account_moid>/<user_moid>/<key_moid>`).

Place the `.pem` file in the project directory (or anywhere readable) and reference both values in `.env`:

```
INTERSIGHT_API_KEY_ID=6514bd3c.../697d0e20.../69fa3115...
INTERSIGHT_API_KEY_FILE=./intersight_api_key.pem
```

---

## Configuration

All configuration is via `.env`. See `.env.example` for the canonical reference.

| Variable | Required | Description |
| --- | :---: | --- |
| `INTERSIGHT_API_KEY_ID` | Yes | The v3 API Key ID from Intersight (3-segment Moid path). |
| `INTERSIGHT_API_KEY_FILE` | Yes | Filesystem path to the `.pem` private key downloaded from Intersight. |
| `INTERSIGHT_BASE_URL` | No | Defaults to `https://intersight.com`. Override only for an on-prem Intersight Virtual Appliance (e.g., `https://appliance.example.com`). |
| `INTERSIGHT_ACCOUNT_NAME` | No | Manual override for the report title. By default the script reads the account name from `/api/v1/iam/Accounts/<moid>`; set this if your role lacks that read. |

---

## Usage

```
python chassis_report.py [--format {csv,pdf}] [-o OUTPUT] [--env-file ENV_FILE] [--debug]
```

### Command-line options

| Option | Default | Description |
| --- | --- | --- |
| `--format {csv,pdf}` | `csv` | Output format. PDF requires `--output`. |
| `-o`, `--output` | (stdout for CSV) | Path to output file. |
| `--env-file` | `.env` | Path to the dotenv file. |
| `--debug` | off | Log each HTTP request URL to stderr (signature redacted). |

### Examples

```bash
# CSV to a file
python chassis_report.py --format csv -o chassis.csv

# PDF
python chassis_report.py --format pdf -o chassis.pdf

# Verbose request logging for troubleshooting
python chassis_report.py --format csv -o chassis.csv --debug
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Report generated successfully. |
| `1` | API or runtime error during execution. |
| `2` | Configuration error (missing env vars, bad key file path, etc.). |

---

## Sample output

```
Chassis Inventory for ACME Corp Lab

Name,Model,Serial,Slots Total,Slots Used,Slots Available
ucs-chassis-2,UCSX-9508,FOX2716P0W5,8,4,4
ucs-chassis-1,UCSB-5108-AC2,FOX2648P3U1,8,4,4
ucs-chassis-3,UCSX-9508,FOX2923P53B,8,7,1
```

Sort order is most-available first, so chassis with free capacity rise to the top. The PDF version uses the same columns and additionally highlights rows with available slots in light green.

---

## Required Intersight permissions

For the report to be accurate, the API key's role must permit read access to all of the following:

| MO | Endpoint | Needed for |
| --- | --- | --- |
| `equipment.Chassis` | `GET /api/v1/equipment/Chasses` | Chassis Name, Model, Serial. |
| `compute.Blade` | `GET /api/v1/compute/Blades` | Slot occupancy by blades. |
| `pci.Node` | `GET /api/v1/pci/Nodes` | Slot occupancy by X-Series PCIe / GPU nodes. |
| `iam.Account` (by Moid) | `GET /api/v1/iam/Accounts/<moid>` | Account name in report title. *Optional* — falls back to `INTERSIGHT_ACCOUNT_NAME` env var. |

The built-in **Read-Only** role grants all of these. If a custom role is in use and the script reports under-utilization (PCIe Nodes missing, etc.), confirm the role includes `pci.Node` reads — that one is sometimes omitted from minimal custom roles.

---

## Slot capacity configuration

The script needs to know how many slots each chassis model has. Intersight does not expose this as a structured field on the chassis MO, so the script consults three sources, in order:

1. **`KNOWN_CAPACITY` manual override** in `chassis_report.py` — empty by default. Add an entry only when source 2 produces the wrong value for a specific model.
2. **Parsed `Description` string** — each chassis carries a Description like `"Cisco Blade Server Chassis, 7U with Eight Vertical Blade Slots"`. The script extracts the slot count from this text automatically. This is the primary path and works for every Cisco chassis we've seen, including new models that aren't in the override table.
3. **Observed-max heuristic** — for chassis where the Description has no recognizable slot count, the highest `SlotId` ever observed across the fleet is used. This is a lower bound: if no chassis of that model is fully populated, capacity will be under-reported.

The stderr output during a run shows which source each model resolved from:

```
Slot capacity by model: UCSB-5108-AC2=8 (Description), UCSX-9508=8 (Description)
```

A value of `(override)` or `(observed max)` in that line tells you the script fell back to source 1 or 3 respectively. If a row in the report shows `?` in the Total / Available columns, no source produced a value — typically a brand-new chassis model whose Description didn't parse and which has no occupants yet. Add the model to `KNOWN_CAPACITY` to fix.

The parser caps recognized slot counts at `MAX_PLAUSIBLE_SLOTS = 8` (the maximum across all current Cisco chassis). Numbers above this in a Description are treated as noise — typically product numbers like `5108` or `9508` that appear in the same sentence. Raise this constant if Cisco ever ships a chassis with more compute slots.

---

## How it works

Data flow:

```
  ┌────────────────────────────────────────────────────────────┐
  │ 1. Load credentials from .env, parse the v3 PEM key.       │
  └─────┬──────────────────────────────────────────────────────┘
        │
  ┌─────▼──────────────────────────────────────────────────────┐
  │ 2. Resolve account name (best-effort GET on iam.Account).  │
  └─────┬──────────────────────────────────────────────────────┘
        │
  ┌─────▼──────────────────────────────────────────────────────┐
  │ 3. Fetch (each call signed independently, paginated):      │
  │       GET /api/v1/equipment/Chasses                        │
  │       GET /api/v1/compute/Blades                           │
  │       GET /api/v1/pci/Nodes                                │
  └─────┬──────────────────────────────────────────────────────┘
        │
  ┌─────▼──────────────────────────────────────────────────────┐
  │ 4. Join client-side:                                       │
  │       blade.EquipmentChassis.Moid -> chassis.Moid          │
  │       pci.Node.ComputeBlade.Moid -> blade.Moid -> chassis  │
  └─────┬──────────────────────────────────────────────────────┘
        │
  ┌─────▼──────────────────────────────────────────────────────┐
  │ 5. Compute used = blades + PCIe nodes per chassis,         │
  │    look up total slots from KNOWN_CAPACITY,                │
  │    sort rows by available descending,                      │
  │    render CSV or PDF.                                      │
  └────────────────────────────────────────────────────────────┘
```

### HTTP Signature signing

Each request is signed with the API key per [draft-cavage-http-signatures-12](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12). The signing string covers `(request-target)`, `host`, `date`, `digest`, and `content-type`. For v3 keys the algorithm is `hs2019` with an ECDSA P-256 / SHA-256 signature in DER encoding. See `sign_headers()` in `chassis_report.py` for the full implementation.

### Two-hop chassis join for PCIe Nodes

`pci.Node` MOs do not carry an `EquipmentChassis` reference. Each one references its X-Fabric-paired `compute.Blade` via `ComputeBlade`. To bucket PCIe Nodes by chassis, the script first builds a `blade_moid → chassis_moid` map from the blades it already fetched, then resolves each PCIe Node's chassis through its paired blade. See `attach_occupants()` for details.

---

## Project layout

```
.
├── chassis_report.py     # Main script
├── requirements.txt      # Python dependencies
├── .env.example          # Configuration template
├── .gitignore            # Excludes .env, *.pem, *.csv, *.pdf, venv/, __pycache__/
└── README.md             # This file
```

### Files excluded from version control

The following are excluded by `.gitignore` and must never be committed:

| Pattern | Reason |
| --- | --- |
| `.env` | Contains the API Key ID. |
| `*.pem` | Private key file. |
| `*.csv`, `*.pdf` | Generated reports — contain real chassis Names and Serial numbers. |
| `.venv/`, `venv/` | Local virtual environments. |
| `__pycache__/`, `*.pyc` | Python bytecode. |

If you fork or clone this repo, generated reports and credentials stay local automatically.
