"""
Bank scenario injector — Banque Atlas coordinated attack (the demo's spine).

This module fires 4 RawThreatRecord events in controlled order to make
PC4's dashboard light up live during the judge pitch. The 4 events
together describe ONE coordinated attack on a fictitious Tunisian bank
(Banque Atlas) with realistic kill-chain progression:

    1. Phishing email impersonating BCT circular              (treasury)
    2. Lateral movement after malware execution               (payment_gateway)
    3. Customer-DB exfiltration to known C2 infrastructure   (customer_db)
    4. SWIFT MT103 anomaly + ransom demand                    (swift_terminal)

IOC CONSISTENCY (the demo punchline):
    The same SHA256 hash, C2 IP, and phishing domain reappear across
    multiple events. PC3's correlation engine should detect them as
    ONE incident, not four — that's the value proposition: an isolated
    SOC sees four alerts; we see one campaign.

ALL IOCs ARE SYNTHETIC:
    * 198.51.100.x and 203.0.113.x are RFC 5737 reserved IPs (never routable)
    * bct-secure-login.tn is a scenario placeholder, clearly tagged in raw_text
    * The SHA256 is fabricated
    * The Bitcoin address is fabricated and would not validate
    Never use real malicious infrastructure here — judges may take screenshots.

Run:
    python -m pc1_data.collectors.bank_scenario_injector            # 4 events, 30s pacing
    python -m pc1_data.collectors.bank_scenario_injector --pace 0   # instant (for tests)
    python -m pc1_data.collectors.bank_scenario_injector --no-push  # dry run, print only
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Iterable, List

import httpx

from shared.schemas import RawThreatRecord


# ──────────────────────────────────────────────────────────────────────────
# Synthetic IOCs (reused across events to support PC3 correlation)
# ──────────────────────────────────────────────────────────────────────────

# Malicious payload hash — appears in events 1 (attached to phishing) and 2
# (executed on the compromised treasury workstation).
MALICIOUS_SHA256 = (
    "a3f8b2c1d4e5f6789012345678901234567890abcdef1234567890abcdef1234"
)

# Phishing site impersonating Banque Centrale de Tunisie. Synthetic.
PHISH_DOMAIN = "bct-secure-login.tn"
PHISH_URL = f"https://{PHISH_DOMAIN}/auth/circular-2026-04"

# Spoofed sender — impersonates BCT but isn't a real BCT address.
PHISH_SENDER = "circulaires@bct-notifications.tn"

# C2 IP — appears in events 3 and 4. RFC 5737 reserved range.
C2_IP = "203.0.113.42"

# Secondary C2 IP for the exfiltration — same operator, different node.
EXFIL_IP = "198.51.100.77"

# Fabricated ransom Bitcoin address.
RANSOM_BTC = "bc1qfak3fak3fak3fak3fak3fak3fak3000000"

# Fictional internal hosts at "Banque Atlas".
HOST_TREASURY = "BCT-WIN-SRV-04"
HOST_PAYMENT_GATEWAY = "PMG-SRV-01"
HOST_CUSTOMER_DB = "CUST-DB-PROD"

# Internal user identity.
COMPROMISED_USER = "treasury_admin"

# SWIFT anomaly details.
ANOMALOUS_BIC = "BANBQTUNXXX"  # fictional Tunisian BIC
MT103_AMOUNT_EUR = 4_800_000


# ──────────────────────────────────────────────────────────────────────────
# Event builders — each returns one RawThreatRecord
# ──────────────────────────────────────────────────────────────────────────


def _event_phishing(t: datetime) -> RawThreatRecord:
    """Event 1 — spearphishing email impersonating BCT circular."""
    raw_text = f"""\
Title: Suspected spearphishing email to treasury inbox
Date: {t.isoformat()}
Source: Internal email gateway (Banque Atlas)
Sector: banking
Asset: treasury

Description:
A spearphishing email impersonating Banque Centrale de Tunisie (BCT) was
delivered to {COMPROMISED_USER}@banque-atlas.tn at {t.strftime('%H:%M UTC')}.
The message claims to be a regulatory circular requiring urgent acknowledgement.

Sender (spoofed): {PHISH_SENDER}
Subject: "[BCT] Circulaire 2026-04 - Mise a jour obligatoire des controles AML"
Reply-to header inconsistency detected (sender domain != reply domain).

The email body contains a link to a credential-harvesting page:
  {PHISH_URL}

A weaponised Excel attachment was included:
  filename: BCT_Circulaire_2026-04.xlsm
  sha256:   {MALICIOUS_SHA256}
  size:     487 KB

Static analysis flagged macro auto-execution and a base64-encoded PowerShell
dropper. The dropper, if executed, beacons to {C2_IP} on TCP/443.

NOTE: scenario / synthetic data — bct-secure-login.tn is not a real domain
and the attachment hash is fabricated for demonstration purposes.
"""
    return RawThreatRecord(
        id=f"scenario:phishing-{t.strftime('%Y%m%dT%H%M%S')}",
        source="scenario",
        raw_text=raw_text,
        timestamp=t,
        sector="banking",
        asset_type="treasury",
    )


def _event_lateral_movement(t: datetime) -> RawThreatRecord:
    """Event 2 — malware executed, lateral move to payment gateway."""
    raw_text = f"""\
Title: Suspicious SMB session — treasury workstation to payment gateway
Date: {t.isoformat()}
Source: Sysmon (Banque Atlas EDR)
Sector: banking
Asset: payment_gateway

Description:
Sysmon Event ID 1 (process creation) on host {HOST_TREASURY} at
{t.strftime('%H:%M UTC')} shows EXCEL.EXE spawning powershell.exe with a
suspicious encoded command. The parent file matches a recent phishing
attachment hash:
  sha256: {MALICIOUS_SHA256}

Roughly 90 seconds later, Sysmon Event ID 3 (network connection) records
an outbound SMB session from {HOST_TREASURY} to {HOST_PAYMENT_GATEWAY} on
TCP/445, authenticated as {COMPROMISED_USER}. This is anomalous — the
treasury workstation does not normally initiate SMB sessions to the
payment-gateway segment.

Subsequently, named-pipe access to \\\\{HOST_PAYMENT_GATEWAY}\\IPC$ was
observed, followed by remote service registration (Sysmon Event ID 13,
registry key modification under HKLM\\SYSTEM\\CurrentControlSet\\Services\\).

This is consistent with an attacker pivoting from the initially compromised
treasury workstation to the payment-gateway server using stolen
credentials. MITRE ATT&CK: T1078 (Valid Accounts), T1021.002 (SMB / Admin
Shares).
"""
    return RawThreatRecord(
        id=f"scenario:lateral-{t.strftime('%Y%m%dT%H%M%S')}",
        source="scenario",
        raw_text=raw_text,
        timestamp=t,
        sector="banking",
        asset_type="payment_gateway",
    )


def _event_exfiltration(t: datetime) -> RawThreatRecord:
    """Event 3 — customer DB exfiltration to known-bad C2."""
    raw_text = f"""\
Title: Large outbound transfer from customer database to external IP
Date: {t.isoformat()}
Source: NetFlow + DLP (Banque Atlas)
Sector: banking
Asset: customer_db

Description:
At {t.strftime('%H:%M UTC')} the DLP system flagged a large HTTPS upload
from {HOST_CUSTOMER_DB} to an external destination:
  destination_ip: {EXFIL_IP}
  destination_port: 443
  bytes_transferred: 2.7 GB
  duration: 11 minutes
  initiating_process: rundll32.exe (anomalous on a database server)

The destination IP {EXFIL_IP} resolves through the same ASN as {C2_IP},
which OSINT feeds attribute to a known infrastructure cluster previously
linked to financial-sector intrusions (Lazarus / FIN7 patterns).

Database query log on {HOST_CUSTOMER_DB} shows a SELECT against the
`customers` and `accounts_payable` tables roughly matching the 2.7 GB
egress size. The query was issued under the {COMPROMISED_USER} session
that originally authenticated from {HOST_TREASURY} (see correlated
lateral-movement event).

This represents probable customer-data exfiltration. MITRE ATT&CK: T1041
(Exfiltration over C2 Channel), T1567 (Exfiltration to Cloud Storage).
PCI-DSS Requirement 3 implicated; GDPR Article 33 72-hour notification clock
has started.
"""
    return RawThreatRecord(
        id=f"scenario:exfil-{t.strftime('%Y%m%dT%H%M%S')}",
        source="scenario",
        raw_text=raw_text,
        timestamp=t,
        sector="banking",
        asset_type="customer_db",
    )


def _event_swift_anomaly(t: datetime) -> RawThreatRecord:
    """Event 4 — SWIFT MT103 anomaly + extortion demand."""
    raw_text = f"""\
Title: SWIFT MT103 anomaly — unauthorised high-value transfer attempt
Date: {t.isoformat()}
Source: SWIFT terminal log (Banque Atlas)
Sector: banking
Asset: swift_terminal

Description:
At {t.strftime('%H:%M UTC')} the SWIFT terminal logs show an MT103
single-customer credit transfer queued for transmission with anomalous
characteristics:
  ordering_customer: Banque Atlas - Treasury Operations
  beneficiary_bic:   {ANOMALOUS_BIC}
  beneficiary_country: jurisdiction with no prior counterparty history
  amount:            EUR {MT103_AMOUNT_EUR:,}
  reference:         "INV-2026-04-URGENT"
  initiated_by:      {COMPROMISED_USER}
  initiation_host:   {HOST_PAYMENT_GATEWAY}

The destination BIC has no transaction history with Banque Atlas and was
queued outside business hours. The infrastructure trail behind the BIC
resolves to the same hosting provider as {C2_IP} — the same C2 cluster
used in the customer-database exfiltration.

Concurrently, an extortion email was received at the executive inbox
demanding a payment of 50 BTC to:
  {RANSOM_BTC}
in exchange for non-publication of the exfiltrated customer records.

The MT103 has been blocked by the payment-screening rule for
new-counterparty / out-of-hours pattern and is awaiting manual review.

MITRE ATT&CK: T1486 (Data Encrypted for Impact - extortion variant),
T1657 (Financial Theft). SWIFT CSP CSCF 2.x notification window: 24 hours.
"""
    return RawThreatRecord(
        id=f"scenario:swift-{t.strftime('%Y%m%dT%H%M%S')}",
        source="scenario",
        raw_text=raw_text,
        timestamp=t,
        sector="banking",
        asset_type="swift_terminal",
    )


def fetch_scenario(start: datetime | None = None) -> List[RawThreatRecord]:
    """Build the 4-event Banque Atlas scenario, with internally-consistent timestamps."""
    t0 = start or datetime.now(timezone.utc)
    return [
        _event_phishing(t0),
        _event_lateral_movement(t0 + timedelta(minutes=2)),
        _event_exfiltration(t0 + timedelta(minutes=15)),
        _event_swift_anomaly(t0 + timedelta(minutes=22)),
    ]


# ──────────────────────────────────────────────────────────────────────────
# API push (mirrors the OTX collector pattern)
# ──────────────────────────────────────────────────────────────────────────


def push_to_api(
    records: Iterable[RawThreatRecord],
    api_url: str = "http://localhost:8000",
    pace_seconds: float = 30.0,
    timeout: float = 5.0,
) -> tuple[int, int]:
    """POST records to /raw with optional pacing for the live demo.

    pace_seconds=0 means instant (for tests). pace_seconds=30 (default)
    means 30 seconds between events — gives the dashboard time to
    visibly react during the pitch.
    """
    ok = 0
    fail = 0
    records = list(records)
    with httpx.Client(timeout=timeout) as client:
        for i, record in enumerate(records):
            try:
                resp = client.post(
                    f"{api_url}/raw",
                    content=record.model_dump_json(),
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                ok += 1
                print(f"[scenario] [{i+1}/{len(records)}] pushed {record.id}  asset={record.asset_type}")
            except httpx.HTTPError as e:
                fail += 1
                print(f"[scenario] FAIL push {record.id}: {e}", file=sys.stderr)
            if pace_seconds > 0 and i < len(records) - 1:
                time.sleep(pace_seconds)
    return ok, fail


# ──────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description="Banque Atlas scenario injector")
    parser.add_argument(
        "--api",
        default=os.getenv("PC1_API_URL", "http://localhost:8000"),
        help="PC1 API base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--pace",
        type=float,
        default=30.0,
        help="Seconds between events (0 = instant, 30 = live demo pacing).",
    )
    parser.add_argument(
        "--no-push",
        action="store_true",
        help="Print events to stdout instead of pushing to the API.",
    )
    args = parser.parse_args()

    records = fetch_scenario()
    print(f"[scenario] Built {len(records)} events for Banque Atlas attack chain.")

    if args.no_push:
        for r in records:
            print(f"\n=== {r.id}  asset={r.asset_type} ===")
            print(r.raw_text)
        return 0

    print(f"[scenario] Pushing to {args.api}/raw with --pace={args.pace}s ...")
    ok, fail = push_to_api(records, api_url=args.api, pace_seconds=args.pace)
    print(f"[scenario] Done. {ok} pushed, {fail} failed.")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
