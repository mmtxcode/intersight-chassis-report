#!/usr/bin/env python3
"""Intersight chassis inventory report.

Reports chassis Name, Model, Serial, and slot utilization.

NOTE: The Intersight REST collection for equipment.Chassis is pluralized as
"Chasses" in the URL path (i.e., /api/v1/equipment/Chasses). The MO type
name is still "equipment.Chassis"; only the collection URL is irregular.

Usage:
    python chassis_report.py --format csv -o chassis.csv
    python chassis_report.py --format pdf -o chassis.pdf
    python chassis_report.py --format csv          # write to stdout
"""

import argparse
import base64
import csv
import hashlib
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from email.utils import formatdate
from pathlib import Path
from urllib.parse import urlencode, urlparse

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from dotenv import load_dotenv

DEFAULT_BASE_URL = "https://intersight.com"
PAGE_SIZE = 100

# Slot capacity per chassis model. Used when no chassis of that model is
# fully populated (so observed-max from blade SlotIds would under-report).
# Add entries as new models appear in your fleet.
KNOWN_CAPACITY = {
    "UCSX-9508": 8,
    "UCSB-5108-AC2": 8,  # 8 half-width slots (or 4 full-width)
}


def load_private_key(path: str):
    """Load an Intersight API key from PEM (PKCS#8 or SEC1) or DER.

    We accept several layouts because Intersight, openssl, and various
    conversion tools each produce slightly different PEM headers.
    """
    with open(path, "rb") as f:
        data = f.read()

    # Strip UTF-8 BOM and normalize line endings — both have caused failures.
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

    blocks = re.findall(rb"-----BEGIN ([A-Z0-9 ]+)-----", data)
    block_names = [b.decode().strip() for b in blocks]

    attempts = []

    # 1. Try as-is. Handles correctly-labeled PEM files.
    try:
        return serialization.load_pem_private_key(data, password=None)
    except Exception as e:
        attempts.append(("PEM as-is", str(e).splitlines()[0]))

    # 2. If the file contains a labeled PEM block whose body is actually a
    #    PKCS#8 PrivateKeyInfo SEQUENCE (a common Intersight quirk), relabel it.
    pem_match = re.search(
        rb"-----BEGIN [A-Z0-9 ]+-----\n(.+?)\n-----END [A-Z0-9 ]+-----",
        data,
        flags=re.DOTALL,
    )
    if pem_match:
        body_b64 = b"".join(pem_match.group(1).split())
        try:
            der = base64.b64decode(body_b64, validate=True)
            try:
                return serialization.load_der_private_key(der, password=None)
            except Exception as e:
                attempts.append(("DER from PEM body", str(e).splitlines()[0]))
        except Exception as e:
            attempts.append(("base64 decode", str(e).splitlines()[0]))

    # 3. Whole file as DER (binary-encoded private key).
    try:
        return serialization.load_der_private_key(data, password=None)
    except Exception as e:
        attempts.append(("DER whole file", str(e).splitlines()[0]))

    found = ", ".join(block_names) if block_names else "no PEM blocks found"
    detail = "\n  ".join(f"{name}: {err}" for name, err in attempts)
    raise RuntimeError(
        f"Could not load private key from {path}\n"
        f"  PEM blocks present: {found}\n"
        f"  Attempts:\n  {detail}\n"
        f"Hint: an Intersight v3 API key file should contain a single block\n"
        f"      labeled '-----BEGIN EC PRIVATE KEY-----' (SEC1) or\n"
        f"      '-----BEGIN PRIVATE KEY-----' (PKCS#8). If you see anything\n"
        f"      else (CERTIFICATE, PUBLIC KEY, RSA PRIVATE KEY) it's the wrong\n"
        f"      file. Regenerate the API key in Intersight and download fresh."
    )


def sign_headers(method: str, url: str, body: bytes, key_id: str, private_key) -> dict:
    """Build Cavage HTTP Signature headers matching Cisco Intersight's spec.

    Signs (request-target), host, date, digest, content-type — the same set
    Cisco's auth docs example uses. v3 API keys are ECDSA P-256 (hs2019);
    v2 keys are RSA SHA-256.
    """
    parsed = urlparse(url)
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    digest = "SHA-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()
    date = formatdate(timeval=None, localtime=False, usegmt=True)
    host = parsed.netloc
    content_type = "application/json"

    signed_order = ["(request-target)", "host", "date", "digest", "content-type"]
    values = {
        "(request-target)": f"{method.lower()} {target}",
        "host": host,
        "date": date,
        "digest": digest,
        "content-type": content_type,
    }
    signing_string = "\n".join(f"{name}: {values[name]}" for name in signed_order)

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        # Intersight expects DER-encoded ECDSA under hs2019 (verified empirically;
        # raw r||s per the literal HTTP-Sigs spec is rejected as invalid).
        algorithm = "hs2019"
        signature = private_key.sign(signing_string.encode(), ec.ECDSA(hashes.SHA256()))
    elif isinstance(private_key, rsa.RSAPrivateKey):
        algorithm = "rsa-sha256"
        signature = private_key.sign(
            signing_string.encode(), padding.PKCS1v15(), hashes.SHA256()
        )
    else:
        raise RuntimeError(f"Unsupported key type: {type(private_key).__name__}")

    sig_b64 = base64.b64encode(signature).decode()
    auth = (
        f'Signature keyId="{key_id}",algorithm="{algorithm}",'
        f'headers="{" ".join(signed_order)}",signature="{sig_b64}"'
    )
    return {
        "Host": host,
        "Date": date,
        "Digest": digest,
        "Content-Type": content_type,
        "Authorization": auth,
        "Accept": "application/json",
    }


def get_account_name(base_url: str, key_id: str, private_key, *, debug: bool = False) -> str | None:
    """Best-effort lookup of the Intersight account display name.

    The first segment of the API key ID is the account Moid. Direct reads by
    Moid often succeed even when the iam.* LIST endpoints are role-blocked.
    Returns None if the read fails or returns no Name.
    """
    account_moid = key_id.split("/", 1)[0]
    url = f"{base_url}/api/v1/iam/Accounts/{account_moid}"
    headers = sign_headers("GET", url, b"", key_id, private_key)
    if debug:
        print(f"DEBUG GET {url}", file=sys.stderr)
    try:
        resp = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        return (resp.json().get("Name") or "").strip() or None
    except ValueError:
        return None


def fetch_all(
    base_url: str,
    path: str,
    params: dict,
    key_id: str,
    private_key,
    *,
    debug: bool = False,
) -> list:
    """Page through an Intersight collection and return all results."""
    all_results = []
    skip = 0
    while True:
        page_params = {**params, "$top": PAGE_SIZE, "$skip": skip}
        url = f"{base_url}{path}?{urlencode(page_params, safe='$,()')}"
        headers = sign_headers("GET", url, b"", key_id, private_key)
        if debug:
            redacted = re.sub(r'signature="[^"]+"', 'signature="<redacted>"', headers["Authorization"])
            print(f"DEBUG GET {url}\n  Authorization: {redacted}", file=sys.stderr)
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Intersight API error {resp.status_code} for GET {path}: "
                f"{resp.text[:300]}"
            )
        page = resp.json().get("Results") or []
        all_results.extend(page)
        if len(page) < PAGE_SIZE:
            return all_results
        skip += PAGE_SIZE


def attach_blades(chassis_list: list, blades: list) -> None:
    """Group blades onto their chassis by Moid. Mutates chassis_list in place."""
    by_chassis = defaultdict(list)
    for blade in blades:
        ref = blade.get("EquipmentChassis") or blade.get("Chassis") or {}
        moid = ref.get("Moid") if isinstance(ref, dict) else None
        if moid:
            by_chassis[moid].append(blade)
    for c in chassis_list:
        c["Blades"] = by_chassis.get(c.get("Moid"), [])


def capacity_by_model(chassis_list: list) -> dict:
    """Resolve total slot count per model.

    Precedence: KNOWN_CAPACITY override → max SlotId observed across the fleet.
    Models with neither return no entry; the report shows '?' for those.
    """
    observed = defaultdict(int)
    for chassis in chassis_list:
        model = chassis.get("Model") or "Unknown"
        for blade in chassis.get("Blades") or []:
            slot = blade.get("SlotId") or 0
            if slot > observed[model]:
                observed[model] = slot

    capacity = {}
    for model in {c.get("Model") or "Unknown" for c in chassis_list}:
        known = KNOWN_CAPACITY.get(model)
        seen = observed.get(model, 0)
        if known and seen > known:
            capacity[model] = seen
        elif known:
            capacity[model] = known
        elif seen:
            capacity[model] = seen
    return capacity


def build_rows(chassis_list: list, capacity: dict) -> list:
    rows = []
    for c in chassis_list:
        model = c.get("Model") or "Unknown"
        blades = c.get("Blades") or []
        used = len(blades)
        total = capacity.get(model, 0)
        if total and used > total:
            total = used  # observed reality wins over the table
        available = total - used if total else None
        rows.append(
            {
                "name": c.get("Name") or "",
                "model": model,
                "serial": c.get("Serial") or "",
                "used": used,
                "total": total if total else None,
                "available": available,
            }
        )
    rows.sort(
        key=lambda r: (r["available"] is None, -(r["available"] or 0), r["model"])
    )
    return rows


def fmt(value):
    return "?" if value is None else str(value)


CSV_HEADER = ["Name", "Model", "Serial", "Slots Total", "Slots Used", "Slots Available"]


def _row_values(r):
    return [r["name"], r["model"], r["serial"],
            fmt(r["total"]), r["used"], fmt(r["available"])]


def write_csv(rows: list, stream, title: str) -> None:
    writer = csv.writer(stream)
    writer.writerow([title])
    writer.writerow([])
    writer.writerow(CSV_HEADER)
    for r in rows:
        writer.writerow(_row_values(r))


def write_pdf(rows: list, path: str, title: str) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import landscape, letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=landscape(letter), title=title)
    story = [
        Paragraph(title, styles["Title"]),
        Paragraph(
            f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
            f"&middot; {len(rows)} chassis",
            styles["Normal"],
        ),
        Spacer(1, 12),
    ]

    data = [CSV_HEADER] + [_row_values(r) for r in rows]

    table = Table(data, repeatRows=1, hAlign="LEFT")
    style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E78")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (3, 1), (-1, -1), "RIGHT"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F7F7")]),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
    )
    for i, r in enumerate(rows, start=1):
        if isinstance(r["available"], int) and r["available"] > 0:
            style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#E2EFDA"))
    table.setStyle(style)
    story.append(table)
    doc.build(story)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--format", choices=["csv", "pdf"], default="csv")
    parser.add_argument("-o", "--output", help="Output file (CSV writes to stdout if omitted)")
    parser.add_argument("--env-file", default=".env", help="Path to .env file (default: .env)")
    parser.add_argument("--debug", action="store_true", help="Print each request URL")
    args = parser.parse_args()

    load_dotenv(args.env_file)
    key_id = os.environ.get("INTERSIGHT_API_KEY_ID", "").strip()
    key_file = os.environ.get("INTERSIGHT_API_KEY_FILE", "").strip()
    base_url = os.environ.get("INTERSIGHT_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

    if not key_id or not key_file:
        print(
            "ERROR: INTERSIGHT_API_KEY_ID and INTERSIGHT_API_KEY_FILE must be set "
            f"(checked {args.env_file}).",
            file=sys.stderr,
        )
        return 2
    if not Path(key_file).is_file():
        print(f"ERROR: API key file not found: {key_file}", file=sys.stderr)
        return 2
    if args.format == "pdf" and not args.output:
        print("ERROR: --output is required for PDF format.", file=sys.stderr)
        return 2

    private_key = load_private_key(key_file)

    account_name = (
        os.environ.get("INTERSIGHT_ACCOUNT_NAME", "").strip()
        or get_account_name(base_url, key_id, private_key, debug=args.debug)
    )
    title = (
        f"Chassis Inventory for {account_name}"
        if account_name
        else "Chassis Inventory"
    )
    if account_name:
        print(f"Account: {account_name}", file=sys.stderr)
    else:
        print(
            "Account name not retrievable (no permission); set "
            "INTERSIGHT_ACCOUNT_NAME in .env to override.",
            file=sys.stderr,
        )

    print(f"Fetching chassis from {base_url} ...", file=sys.stderr)
    # NOTE: the URL path is "Chasses" (Intersight's irregular plural), even
    # though the MO type is "equipment.Chassis". Using /equipment/Chassis
    # returns 403 InvalidUrl.
    chassis = fetch_all(
        base_url,
        "/api/v1/equipment/Chasses",
        {"$select": "Moid,Name,Model,Serial"},
        key_id,
        private_key,
        debug=args.debug,
    )
    print(f"  {len(chassis)} chassis returned.", file=sys.stderr)

    print("Fetching blades ...", file=sys.stderr)
    blades = fetch_all(
        base_url,
        "/api/v1/compute/Blades",
        {"$select": "Moid,SlotId,EquipmentChassis"},
        key_id,
        private_key,
        debug=args.debug,
    )
    print(f"  {len(blades)} blades returned.", file=sys.stderr)

    attach_blades(chassis, blades)
    capacity = capacity_by_model(chassis)
    if capacity:
        models = ", ".join(f"{m}={n}" for m, n in sorted(capacity.items()))
        print(f"  Slot capacity by model: {models}", file=sys.stderr)

    rows = build_rows(chassis, capacity)

    if args.format == "csv":
        if args.output:
            with open(args.output, "w", newline="") as f:
                write_csv(rows, f, title)
            print(f"Wrote {args.output}", file=sys.stderr)
        else:
            write_csv(rows, sys.stdout, title)
    else:
        write_pdf(rows, args.output, title)
        print(f"Wrote {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
