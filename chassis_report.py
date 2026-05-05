#!/usr/bin/env python3
"""Intersight chassis inventory report.

Reports chassis Name, Model, Serial, and slot utilization. Output as CSV or
PDF, sorted with the most-available chassis at the top so it's easy to see
where new servers can be racked.

Data flow:
    1. Authenticate to Intersight via HTTP Signature using a v3 API key
       (ECDSA P-256). See sign_headers() for the spec details.
    2. Look up the account display name (best-effort) for the report title.
    3. Fetch all chassis (/equipment/Chasses) and all blades (/compute/Blades).
    4. Join blades onto chassis by Moid, count slots used per chassis,
       resolve total slot count from a model->capacity table (with an
       observed-max fallback for unknown models).
    5. Render to CSV or PDF.

NOTE on URL: the REST collection for equipment.Chassis is pluralized as
"Chasses" (irregular). The MO type name is still "equipment.Chassis"; only
the collection URL is irregular. /api/v1/equipment/Chassis returns 403.

Usage:
    python chassis_report.py --format csv -o chassis.csv
    python chassis_report.py --format pdf -o chassis.pdf
    python chassis_report.py --format csv          # write to stdout
    python chassis_report.py ... --debug           # log request URLs
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
# `cryptography` provides the asymmetric-key primitives we use to sign each
# HTTP request. We need ec (ECDSA, for v3 keys), rsa+padding (for legacy v2
# keys), and the serialization helpers for loading PEM/DER files.
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from dotenv import load_dotenv

# Default Intersight SaaS endpoint. Override via INTERSIGHT_BASE_URL in .env
# only if pointing at an on-prem Intersight Virtual Appliance.
DEFAULT_BASE_URL = "https://intersight.com"

# Intersight caps page size at 1000; we use 100 to keep error messages and
# debug logs at a manageable size while still being efficient.
PAGE_SIZE = 100

# Total slots per chassis model. Intersight does NOT expose total slot count
# on the equipment.Chassis MO, so we keep our own table here. If a chassis
# model isn't in this table, the report falls back to the highest SlotId
# observed across the fleet (a lower bound — see capacity_by_model()).
KNOWN_CAPACITY = {
    "UCSX-9508":     8,  # X-Series chassis
    "UCSB-5108-AC2": 8,  # 8 half-width slots (or 4 full-width)
}


def load_private_key(path: str):
    """Load an Intersight API key from PEM (PKCS#8 or SEC1) or DER.

    PEM files have two parts: header lines (-----BEGIN ...-----) and a
    base64-encoded ASN.1 body. The header tells the parser which structure
    to expect (SEC1 ECPrivateKey vs PKCS#8 PrivateKeyInfo). Some tools and
    Intersight downloads put PKCS#8 content inside a SEC1-labeled wrapper,
    which the strict PEM loader rejects with an opaque ASN.1 tag error.

    This loader tries the strict path first, then falls back to extracting
    the body and decoding it as DER directly — that handles the mismatched-
    headers case without altering the user's file.
    """
    with open(path, "rb") as f:
        data = f.read()

    # Tools sometimes prepend a UTF-8 BOM or use Windows line endings;
    # both break the strict ASN.1 parser. Normalize before attempting load.
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

    # Capture which PEM blocks the file contains so we can include them in
    # the error message if every load attempt fails — much more diagnostic
    # than "ASN.1 parsing error" by itself.
    blocks = re.findall(rb"-----BEGIN ([A-Z0-9 ]+)-----", data)
    block_names = [b.decode().strip() for b in blocks]

    attempts = []

    # Path 1: the strict loader. Works for correctly-labeled files where
    # the PEM header matches the body's actual encoding.
    try:
        return serialization.load_pem_private_key(data, password=None)
    except Exception as e:
        attempts.append(("PEM as-is", str(e).splitlines()[0]))

    # Path 2: extract the base64 body, decode to DER, then let the DER
    # loader figure out what's actually inside (it autodetects PKCS#8 vs
    # SEC1). This is the path that recovers from mislabeled PEMs.
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

    # Path 3: the whole file might be raw DER bytes (rare, but possible
    # if someone stripped the PEM wrapper).
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
    """Build Cavage HTTP Signature headers for an Intersight request.

    Intersight does not use an API key as a bearer token. Instead, every
    request is signed: a deterministic "signing string" is built from a
    chosen subset of the request's headers, hashed, and signed with the
    private key. The receiver (Intersight) verifies the signature using the
    public key that was registered when the API key was created.

    Spec: draft-cavage-http-signatures-12, with algorithm="hs2019".
    Cisco docs: https://intersight.com/apidocs/introduction/security/auth/

    Returns a dict of headers to attach to the outgoing request.
    """
    # --- Inputs that must match exactly what's sent on the wire ---
    parsed = urlparse(url)
    # The "(request-target)" pseudo-header includes the lowercased method
    # and the full path-and-query, e.g. "get /api/v1/foo?$top=10".
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    # SHA-256 of the request body, base64-encoded. Always present even when
    # the body is empty (digest of zero bytes is a fixed value).
    digest = "SHA-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()
    # RFC 7231 / 2822 GMT date. Intersight rejects signatures with a Date
    # more than ~15 minutes off — clock skew is the most common false
    # negative when this code is reused on a freshly imaged machine.
    date = formatdate(timeval=None, localtime=False, usegmt=True)
    host = parsed.netloc
    content_type = "application/json"

    # --- Build the signing string ---
    # Order matters: the Authorization header advertises this same order in
    # the headers="..." field, and Intersight reproduces the signing string
    # in that exact order to verify. As long as our string and our headers
    # field agree, the order itself is flexible.
    signed_order = ["(request-target)", "host", "date", "digest", "content-type"]
    values = {
        "(request-target)": f"{method.lower()} {target}",
        "host": host,
        "date": date,
        "digest": digest,
        "content-type": content_type,
    }
    # Format per Cavage spec: "<lowercased-name>: <value>", LF-joined (no CR).
    signing_string = "\n".join(f"{name}: {values[name]}" for name in signed_order)

    # --- Sign the signing string with the private key ---
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        # v3 keys are ECDSA P-256, advertised as algorithm="hs2019".
        # Intersight expects the signature in OpenSSL's native DER (ASN.1)
        # form, which is what cryptography's .sign() returns. Note this
        # diverges from the literal HTTP-Sigs spec, which calls for raw
        # r||s (IEEE P1363); raw is rejected by Intersight's verifier as
        # iam_api_key_is_invalid.
        algorithm = "hs2019"
        signature = private_key.sign(signing_string.encode(), ec.ECDSA(hashes.SHA256()))
    elif isinstance(private_key, rsa.RSAPrivateKey):
        # Legacy v2 path. Kept for compatibility — new keys should be v3.
        algorithm = "rsa-sha256"
        signature = private_key.sign(
            signing_string.encode(), padding.PKCS1v15(), hashes.SHA256()
        )
    else:
        raise RuntimeError(f"Unsupported key type: {type(private_key).__name__}")

    # --- Assemble the Authorization header ---
    # The base64-encoded binary signature, plus metadata the verifier needs:
    # the keyId (so it knows which public key to check against) and the list
    # of headers we signed (so it can reconstruct the signing string).
    sig_b64 = base64.b64encode(signature).decode()
    auth = (
        f'Signature keyId="{key_id}",algorithm="{algorithm}",'
        f'headers="{" ".join(signed_order)}",signature="{sig_b64}"'
    )
    # All five "signed" header values must be sent verbatim with the request,
    # otherwise the verifier will fail to reproduce the signing string.
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
    """Page through an Intersight collection and return every result.

    Intersight uses OData-style paging: $top sets the page size, $skip is
    the offset. We keep requesting pages until we get a short page (fewer
    than PAGE_SIZE rows), which signals the end of the collection.
    """
    all_results = []
    skip = 0
    while True:
        # Each page needs a fresh signature: the URL changes (different
        # $skip) and the Date header advances, so the prior signing string
        # is no longer valid.
        page_params = {**params, "$top": PAGE_SIZE, "$skip": skip}
        # safe="$,()" tells urlencode to leave OData syntax characters
        # ($select, $filter, list separators, function calls) intact.
        # urllib3 will not re-encode the URL once we hand it to requests,
        # so what we sign here is what goes on the wire.
        url = f"{base_url}{path}?{urlencode(page_params, safe='$,()')}"
        headers = sign_headers("GET", url, b"", key_id, private_key)
        if debug:
            # Don't leak the actual signature into log output.
            redacted = re.sub(r'signature="[^"]+"', 'signature="<redacted>"', headers["Authorization"])
            print(f"DEBUG GET {url}\n  Authorization: {redacted}", file=sys.stderr)
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            # Truncate the body — Intersight returns verbose CSP/security
            # headers in error responses that drown out the actual error.
            raise RuntimeError(
                f"Intersight API error {resp.status_code} for GET {path}: "
                f"{resp.text[:300]}"
            )
        page = resp.json().get("Results") or []
        all_results.extend(page)
        # Short page = end of results. Stops the loop cleanly without
        # needing a separate Count query.
        if len(page) < PAGE_SIZE:
            return all_results
        skip += PAGE_SIZE


def attach_blades(chassis_list: list, blades: list) -> None:
    """Group blades onto their parent chassis by Moid (mutates in place).

    Each blade carries a relationship object that points at its chassis:
        {"EquipmentChassis": {"Moid": "<chassis-moid>", "ObjectType": ...}}
    We do this join client-side rather than via $expand=Blades because
    $expand can require additional permissions on the expanded type.
    """
    # Bucket blades by chassis Moid in one pass.
    by_chassis = defaultdict(list)
    for blade in blades:
        # Some Intersight responses use "Chassis" as the key instead of
        # "EquipmentChassis"; check both for forward compatibility.
        ref = blade.get("EquipmentChassis") or blade.get("Chassis") or {}
        moid = ref.get("Moid") if isinstance(ref, dict) else None
        if moid:
            by_chassis[moid].append(blade)
    # Attach the bucket to each chassis. Empty list for chassis with no blades.
    for c in chassis_list:
        c["Blades"] = by_chassis.get(c.get("Moid"), [])


def capacity_by_model(chassis_list: list) -> dict:
    """Determine total slot count per chassis model.

    Two sources, in priority order:
      1. KNOWN_CAPACITY table — the authoritative answer.
      2. Highest SlotId observed across the fleet for that model — a lower
         bound. Useful only when at least one chassis of that model has a
         blade in its top slot.

    Returns {model: total_slots}. Models with neither source are absent
    from the result; build_rows() emits "?" for those rows.
    """
    # First pass: find the max SlotId per model across all blades in the fleet.
    observed = defaultdict(int)
    for chassis in chassis_list:
        model = chassis.get("Model") or "Unknown"
        for blade in chassis.get("Blades") or []:
            slot = blade.get("SlotId") or 0
            if slot > observed[model]:
                observed[model] = slot

    # Second pass: pick the best source for each distinct model present.
    capacity = {}
    for model in {c.get("Model") or "Unknown" for c in chassis_list}:
        known = KNOWN_CAPACITY.get(model)
        seen = observed.get(model, 0)
        if known and seen > known:
            # Real data exceeds our table — trust the data and let the user
            # update KNOWN_CAPACITY. (Should not happen for healthy fleets.)
            capacity[model] = seen
        elif known:
            capacity[model] = known
        elif seen:
            capacity[model] = seen
        # else: unknown model with no observed blades → omit, row shows "?"
    return capacity


def build_rows(chassis_list: list, capacity: dict) -> list:
    """Turn raw chassis dicts into report rows, sorted most-available first."""
    rows = []
    for c in chassis_list:
        model = c.get("Model") or "Unknown"
        blades = c.get("Blades") or []
        used = len(blades)
        total = capacity.get(model, 0)
        # Defensive: a chassis with more blades than our table allows means
        # the table is wrong — believe the live data instead of the table.
        if total and used > total:
            total = used
        # `available` is None (not 0) when total is unknown — keeps "?" in
        # the report distinct from a chassis that's genuinely full.
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
    # Sort: most-available first, unknown-capacity rows pushed to the bottom.
    # Tuple sort: (is_unknown_bool, -available, model) — booleans sort False
    # before True, so known rows come first; the negative `available` makes
    # higher counts sort earlier within those.
    rows.sort(
        key=lambda r: (r["available"] is None, -(r["available"] or 0), r["model"])
    )
    return rows


def fmt(value):
    """Render None as '?' so unknown values are visually distinct from 0."""
    return "?" if value is None else str(value)


# Single source of truth for column order — both writers read this.
CSV_HEADER = ["Name", "Model", "Serial", "Slots Total", "Slots Used", "Slots Available"]


def _row_values(r):
    """Convert a row dict to a list ordered to match CSV_HEADER."""
    return [r["name"], r["model"], r["serial"],
            fmt(r["total"]), r["used"], fmt(r["available"])]


def write_csv(rows: list, stream, title: str) -> None:
    """Write the report as CSV: title row, blank row, header, data rows."""
    writer = csv.writer(stream)
    # Title as a single-cell first row. Blank separator row makes Excel /
    # Numbers display the title cleanly above the table.
    writer.writerow([title])
    writer.writerow([])
    writer.writerow(CSV_HEADER)
    for r in rows:
        writer.writerow(_row_values(r))


def write_pdf(rows: list, path: str, title: str) -> None:
    """Render the report as a landscape-letter PDF using reportlab.

    Imports are kept inside the function so that CSV-only runs don't pay
    the reportlab import cost (it's the slowest of our dependencies to load).
    """
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

    # Same column order/values as CSV — single source of truth.
    data = [CSV_HEADER] + [_row_values(r) for r in rows]

    # Table style — coordinates are (col, row); -1 means "last".
    table = Table(data, repeatRows=1, hAlign="LEFT")
    style = TableStyle(
        [
            # Header row: dark blue background, bold white text.
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E78")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            # Numeric columns (Slots Total/Used/Available, indices 3-5) right-aligned.
            ("ALIGN", (3, 1), (-1, -1), "RIGHT"),
            # Thin grid + alternating row stripe for readability.
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F7F7")]),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
    )
    # Highlight rows with free slots in light green so they pop visually —
    # these are the chassis where a new blade can land.
    for i, r in enumerate(rows, start=1):
        if isinstance(r["available"], int) and r["available"] > 0:
            style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#E2EFDA"))
    table.setStyle(style)
    story.append(table)
    doc.build(story)


def main() -> int:
    # --- 1. Parse arguments ---
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--format", choices=["csv", "pdf"], default="csv")
    parser.add_argument("-o", "--output", help="Output file (CSV writes to stdout if omitted)")
    parser.add_argument("--env-file", default=".env", help="Path to .env file (default: .env)")
    parser.add_argument("--debug", action="store_true", help="Print each request URL")
    args = parser.parse_args()

    # --- 2. Load credentials and configuration from .env ---
    # python-dotenv reads the file and exports each line as an env var, so
    # everything below uses os.environ regardless of source.
    load_dotenv(args.env_file)
    key_id = os.environ.get("INTERSIGHT_API_KEY_ID", "").strip()
    key_file = os.environ.get("INTERSIGHT_API_KEY_FILE", "").strip()
    base_url = os.environ.get("INTERSIGHT_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

    # Validate inputs early — fail loud rather than running into a cryptic
    # error 30 seconds in.
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
        # PDF can't go to stdout (binary, plus needs a seekable file).
        print("ERROR: --output is required for PDF format.", file=sys.stderr)
        return 2

    private_key = load_private_key(key_file)

    # --- 3. Resolve report title (account name) ---
    # Explicit env var wins; otherwise look it up via the API. If both fail,
    # fall back to a generic title rather than blocking the whole report.
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

    # --- 4. Fetch raw data from Intersight ---
    print(f"Fetching chassis from {base_url} ...", file=sys.stderr)
    # NOTE: the URL path is "Chasses" (Intersight's irregular plural), even
    # though the MO type is "equipment.Chassis". Using /equipment/Chassis
    # returns 403 InvalidUrl. $select limits the payload to fields we use.
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
    # We fetch blades separately rather than $expand=Blades on the chassis
    # call so that the chassis read works even if the role lacks read on
    # compute.Blade (and so blade fetch failures degrade gracefully).
    blades = fetch_all(
        base_url,
        "/api/v1/compute/Blades",
        {"$select": "Moid,SlotId,EquipmentChassis"},
        key_id,
        private_key,
        debug=args.debug,
    )
    print(f"  {len(blades)} blades returned.", file=sys.stderr)

    # --- 5. Compute the report ---
    attach_blades(chassis, blades)
    capacity = capacity_by_model(chassis)
    if capacity:
        # Print resolved capacity per model — handy when verifying that an
        # unfamiliar model is being recognized correctly.
        models = ", ".join(f"{m}={n}" for m, n in sorted(capacity.items()))
        print(f"  Slot capacity by model: {models}", file=sys.stderr)

    rows = build_rows(chassis, capacity)

    # --- 6. Write the chosen output format ---
    if args.format == "csv":
        if args.output:
            # newline="" prevents csv.writer from inserting blank lines on
            # Windows (the csv module handles line endings itself).
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
