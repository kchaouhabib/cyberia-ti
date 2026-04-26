"""
IOC threat-type classifier — PC2, Stage 02, Phase 2.

Classifies each IOC into one of 5 threat types:
  phishing | malware | lateral_movement | exfiltration | c2

Model: LogisticRegression on hand-crafted features (IOC type + value patterns + source).
Training set: ~200 samples biased toward financial-sector attacks (FIN7, Carbanak, Lazarus).
Saved to data/models/classifier.pkl — loaded lazily on first call.
"""

import os
import pickle
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin

MODEL_PATH = Path("data/models/classifier.pkl")

# ── Training data ───────────────────────────────────────────────────────────
# Format: (ioc_value, ioc_type, source, label)
# Biased toward financial-attack patterns per BATTLE_PLAN Phase 2 requirements.

_TRAINING_DATA = [
    # ── PHISHING ──────────────────────────────────────────────────────────
    ("secure-bctonline.com",            "domain", "otx",          "phishing"),
    ("banqueatlas-login.com",           "domain", "otx",          "phishing"),
    ("swift-verification-portal.net",   "domain", "otx",          "phishing"),
    ("bctonline-secure.xyz",            "domain", "scenario",     "phishing"),
    ("paiement-atlas-verify.com",       "domain", "scenario",     "phishing"),
    ("clientportal-banque.net",         "domain", "urlhaus",      "phishing"),
    ("update-swiftnet.com",             "domain", "urlhaus",      "phishing"),
    ("https://phish-bank.ru/login",     "url",    "urlhaus",      "phishing"),
    ("https://secure-bankatlas.tk/",    "url",    "urlhaus",      "phishing"),
    ("https://bctonline-reset.xyz/",    "url",    "urlhaus",      "phishing"),
    ("https://swift-auth.ru/verify",    "url",    "urlhaus",      "phishing"),
    ("https://login-banque-atlas.ml/",  "url",    "scenario",     "phishing"),
    ("https://treasury-update.ga/",     "url",    "scenario",     "phishing"),
    ("https://account-verify-bct.cf/",  "url",    "scenario",     "phishing"),
    ("https://ib-secure-login.tk/auth", "url",    "urlhaus",      "phishing"),
    ("bct-circular-update.com",         "domain", "otx",          "phishing"),
    ("e-banking-secure-atlas.net",      "domain", "otx",          "phishing"),
    ("swift-cscf-advisory.org",         "domain", "otx",          "phishing"),
    ("payment-gateway-verify.com",      "domain", "urlhaus",      "phishing"),
    ("https://fin7-lure.com/invoice",   "url",    "threatfox",    "phishing"),
    ("treasury-docs-bct.com",           "domain", "scenario",     "phishing"),
    ("https://carbanak-phish.net/doc",  "url",    "threatfox",    "phishing"),
    ("bankatlas-secure-id.com",         "domain", "scenario",     "phishing"),
    ("https://lazarus-bait.xyz/swift",  "url",    "threatfox",    "phishing"),
    ("online-banking-atlas.ml",         "domain", "urlhaus",      "phishing"),
    ("https://fake-swift-portal.ru/",   "url",    "urlhaus",      "phishing"),
    ("swift-notice-bct.com",            "domain", "scenario",     "phishing"),
    ("https://atm-malware-dl.xyz/",     "url",    "urlhaus",      "phishing"),
    ("bct-advisory-2024.net",           "domain", "otx",          "phishing"),
    ("https://spearphish-fin7.com/xls", "url",    "threatfox",    "phishing"),
    ("payment-form-atlas.com",          "domain", "scenario",     "phishing"),
    ("e-statement-secure.net",          "domain", "urlhaus",      "phishing"),
    ("swift-mt103-verify.com",          "domain", "scenario",     "phishing"),
    ("login-banque-secure.xyz",         "domain", "urlhaus",      "phishing"),
    ("https://dridex-banker.ru/drop",   "url",    "threatfox",    "phishing"),
    ("customer-portal-atlas.tk",        "domain", "scenario",     "phishing"),
    ("bct-circular-pdf.com",            "domain", "scenario",     "phishing"),
    ("swift-terminal-update.net",       "domain", "urlhaus",      "phishing"),
    ("https://trickbot-banker.com/",    "url",    "threatfox",    "phishing"),
    ("atlas-treasury-secure.com",       "domain", "scenario",     "phishing"),
    # Generic phishing — no banking keywords, tests real generalization
    ("document-shared-preview.com",     "domain", "urlhaus",      "phishing"),
    ("invoice-pending-review.net",      "domain", "urlhaus",      "phishing"),
    ("account-suspended-verify.xyz",    "domain", "urlhaus",      "phishing"),
    ("staff-it-helpdesk-reset.com",     "domain", "otx",          "phishing"),
    ("hr-onboarding-portal.tk",         "domain", "otx",          "phishing"),
    ("https://docs-share-link.ru/view", "url",    "urlhaus",      "phishing"),
    ("https://mail-reset-confirm.xyz/", "url",    "urlhaus",      "phishing"),
    ("https://file-access-denied.ml/",  "url",    "scenario",     "phishing"),
    ("https://support-ticket-open.ga/", "url",    "urlhaus",      "phishing"),
    ("notification-alert-secure.net",   "domain", "threatfox",    "phishing"),

    # ── MALWARE ───────────────────────────────────────────────────────────
    ("a3f1e2b4c5d6e7f8a3f1e2b4c5d6e7f8a3f1e2b4c5d6e7f8a3f1e2b4c5d6e7f8", "hash_sha256", "malwarebazaar", "malware"),
    ("d41d8cd98f00b204e9800998ecf8427e", "hash_md5",    "malwarebazaar", "malware"),
    ("5f4dcc3b5aa765d61d8327deb882cf99", "hash_md5",    "malwarebazaar", "malware"),
    ("e99a18c428cb38d5f260853678922e03", "hash_md5",    "malwarebazaar", "malware"),
    ("b14a7b8059d9c055954c92674ce60032", "hash_md5",    "malwarebazaar", "malware"),
    ("098f6bcd4621d373cade4e832627b4f6", "hash_md5",    "malwarebazaar", "malware"),
    ("1234567890abcdef1234567890abcdef", "hash_md5",    "malwarebazaar", "malware"),
    ("aabbccddeeff00112233445566778899", "hash_md5",    "malwarebazaar", "malware"),
    ("deadbeefdeadbeefdeadbeefdeadbeef", "hash_md5",    "otx",           "malware"),
    ("cafebabecafebabecafebabecafebabe", "hash_md5",    "threatfox",     "malware"),
    ("f1e2d3c4b5a6978869504132abcdef01", "hash_md5",    "malwarebazaar", "malware"),
    ("11223344556677889900aabbccddeeff", "hash_md5",    "malwarebazaar", "malware"),
    ("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "hash_md5",   "threatfox",     "malware"),
    ("0011223344556677889900aabbccddee", "hash_md5",    "malwarebazaar", "malware"),
    ("abcdef0123456789abcdef0123456789", "hash_md5",    "malwarebazaar", "malware"),
    ("b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3", "hash_sha256", "malwarebazaar", "malware"),
    ("c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4", "hash_sha256", "threatfox",     "malware"),
    ("carbanak-dropper.exe sha256abc",  "hash_sha256",  "otx",           "malware"),
    ("dridex-payload-v4.dll",           "hash_md5",     "malwarebazaar", "malware"),
    ("trickbot-banking-module.exe",     "hash_md5",     "malwarebazaar", "malware"),
    ("emotet-epoch4-loader.dll",        "hash_md5",     "malwarebazaar", "malware"),
    ("CVE-2021-44228",                  "cve",          "otx",           "malware"),
    ("CVE-2023-23397",                  "cve",          "otx",           "malware"),
    ("CVE-2021-34527",                  "cve",          "otx",           "malware"),
    ("CVE-2020-1472",                   "cve",          "otx",           "malware"),
    ("CVE-2019-0708",                   "cve",          "otx",           "malware"),
    ("CVE-2022-30190",                  "cve",          "otx",           "malware"),
    ("CVE-2021-26855",                  "cve",          "otx",           "malware"),
    ("CVE-2023-28252",                  "cve",          "threatfox",     "malware"),
    ("CVE-2022-41082",                  "cve",          "otx",           "malware"),
    ("CVE-2021-40444",                  "cve",          "otx",           "malware"),

    # ── LATERAL MOVEMENT ──────────────────────────────────────────────────
    ("10.0.5.22",   "ip", "scenario",  "lateral_movement"),
    ("10.0.5.45",   "ip", "scenario",  "lateral_movement"),
    ("10.0.5.100",  "ip", "scenario",  "lateral_movement"),
    ("172.16.0.10", "ip", "scenario",  "lateral_movement"),
    ("172.16.0.25", "ip", "scenario",  "lateral_movement"),
    ("172.16.1.5",  "ip", "scenario",  "lateral_movement"),
    ("172.20.10.3", "ip", "scenario",  "lateral_movement"),
    ("172.20.10.8", "ip", "scenario",  "lateral_movement"),
    ("psexec-lateral.exe",              "hash_md5",  "scenario",    "lateral_movement"),
    ("mimikatz-lsass-dump.exe",         "hash_md5",  "scenario",    "lateral_movement"),
    ("wce-windows-cred.exe",            "hash_md5",  "malwarebazaar","lateral_movement"),
    ("impacket-secretsdump",            "hash_md5",  "otx",         "lateral_movement"),
    ("cobalt-strike-beacon.dll",        "hash_md5",  "malwarebazaar","lateral_movement"),
    ("CVE-2017-0144",                   "cve",       "otx",         "lateral_movement"),
    ("CVE-2017-0145",                   "cve",       "otx",         "lateral_movement"),
    ("CVE-2020-0796",                   "cve",       "otx",         "lateral_movement"),
    ("pass-the-hash-tool.exe",          "hash_md5",  "scenario",    "lateral_movement"),
    ("golden-ticket-kerberos.ps1",      "hash_md5",  "scenario",    "lateral_movement"),
    ("rdp-brute-treasury.exe",          "hash_md5",  "scenario",    "lateral_movement"),
    ("smb-pivot-payment-gw.exe",        "hash_md5",  "scenario",    "lateral_movement"),
    ("treasury-workstation-pivot",      "hash_md5",  "scenario",    "lateral_movement"),
    ("payment-server-recon.ps1",        "hash_md5",  "scenario",    "lateral_movement"),
    ("lateral-swift-terminal.bat",      "hash_md5",  "scenario",    "lateral_movement"),
    ("wmi-exec-banking.vbs",            "hash_md5",  "scenario",    "lateral_movement"),
    ("scheduled-task-persist.ps1",      "hash_md5",  "scenario",    "lateral_movement"),
    ("token-impersonation.exe",         "hash_md5",  "malwarebazaar","lateral_movement"),
    ("process-injection-lsass.dll",     "hash_md5",  "malwarebazaar","lateral_movement"),
    ("dcsync-attack-tool.exe",          "hash_md5",  "otx",         "lateral_movement"),
    ("bloodhound-ad-enum.exe",          "hash_md5",  "otx",         "lateral_movement"),
    ("kerbrute-spray.exe",              "hash_md5",  "otx",         "lateral_movement"),

    # ── EXFILTRATION ──────────────────────────────────────────────────────
    ("185.220.101.45",  "ip",  "otx",       "exfiltration"),
    ("91.108.4.0",      "ip",  "otx",       "exfiltration"),
    ("194.165.16.10",   "ip",  "otx",       "exfiltration"),
    ("77.73.134.50",    "ip",  "threatfox", "exfiltration"),
    ("185.100.87.202",  "ip",  "otx",       "exfiltration"),
    ("45.142.212.100",  "ip",  "threatfox", "exfiltration"),
    ("91.92.109.8",     "ip",  "otx",       "exfiltration"),
    ("185.234.218.40",  "ip",  "otx",       "exfiltration"),
    ("https://transfer.sh/upload/data",        "url", "scenario",   "exfiltration"),
    ("https://anonfiles.com/upload/db",        "url", "scenario",   "exfiltration"),
    ("https://mega.nz/upload/custdata",        "url", "scenario",   "exfiltration"),
    ("https://dropbox.lazarus-exfil.com/put",  "url", "threatfox",  "exfiltration"),
    ("https://paste-data-bank.onion/",         "url", "otx",        "exfiltration"),
    ("https://exfil-swift-data.ru/post",       "url", "scenario",   "exfiltration"),
    ("https://fin7-drop.net/recv",             "url", "threatfox",  "exfiltration"),
    ("customer-data-exfil.exe",         "hash_md5",  "scenario",    "exfiltration"),
    ("cardholder-dump-tool.exe",        "hash_md5",  "scenario",    "exfiltration"),
    ("swift-transaction-stealer.dll",   "hash_md5",  "malwarebazaar","exfiltration"),
    ("db-dump-encrypt.ps1",             "hash_md5",  "scenario",    "exfiltration"),
    ("account-harvest-atlas.exe",       "hash_md5",  "scenario",    "exfiltration"),
    ("CVE-2019-19781",                  "cve",       "otx",         "exfiltration"),
    ("CVE-2021-22986",                  "cve",       "otx",         "exfiltration"),
    ("CVE-2022-22954",                  "cve",       "otx",         "exfiltration"),
    ("data-exfil-dns-tunnel.exe",       "hash_md5",  "otx",         "exfiltration"),
    ("swift-mt103-stealer.dll",         "hash_md5",  "malwarebazaar","exfiltration"),
    ("pci-card-scraper.exe",            "hash_md5",  "malwarebazaar","exfiltration"),
    ("https://lazarus-recv.net/bin",    "url",       "threatfox",   "exfiltration"),
    ("https://carbanak-recv.ru/data",   "url",       "threatfox",   "exfiltration"),
    ("109.234.39.14",   "ip",  "otx",       "exfiltration"),
    ("5.188.86.172",    "ip",  "threatfox", "exfiltration"),

    # ── C2 ────────────────────────────────────────────────────────────────
    ("c2.lazarus-update.net",           "domain", "threatfox",  "c2"),
    ("carbanak-c2.ru",                  "domain", "otx",        "c2"),
    ("fin7-beacon.com",                 "domain", "threatfox",  "c2"),
    ("cobalt-c2-panel.net",             "domain", "threatfox",  "c2"),
    ("silence-group-c2.org",            "domain", "otx",        "c2"),
    ("emotet-c2-banking.com",           "domain", "malwarebazaar","c2"),
    ("trickbot-c2-module.net",          "domain", "malwarebazaar","c2"),
    ("dridex-c2-server.ru",             "domain", "malwarebazaar","c2"),
    ("https://c2.fin7-ops.com/beacon",  "url",    "threatfox",  "c2"),
    ("https://lazarus-c2.net/update",   "url",    "threatfox",  "c2"),
    ("https://carbanak-panel.ru/gate",  "url",    "threatfox",  "c2"),
    ("https://cobalt-c2.net/check",     "url",    "threatfox",  "c2"),
    ("https://trickbot-gtag.com/",      "url",    "malwarebazaar","c2"),
    ("https://emotet-epoch.com/cmd",    "url",    "malwarebazaar","c2"),
    ("185.220.101.1",   "ip",  "threatfox", "c2"),
    ("185.220.101.2",   "ip",  "threatfox", "c2"),
    ("194.165.16.80",   "ip",  "otx",       "c2"),
    ("45.142.212.200",  "ip",  "threatfox", "c2"),
    ("91.108.56.100",   "ip",  "otx",       "c2"),
    ("185.100.87.100",  "ip",  "threatfox", "c2"),
    ("77.73.134.10",    "ip",  "threatfox", "c2"),
    ("beacon-cs-atlas.com",             "domain", "scenario",   "c2"),
    ("c2-treasury-implant.net",         "domain", "scenario",   "c2"),
    ("payment-gw-backdoor.ru",          "domain", "scenario",   "c2"),
    ("https://cs-beacon-bank.ru/pipe",  "url",    "scenario",   "c2"),
    ("https://implant-atlas.net/poll",  "url",    "scenario",   "c2"),
    ("https://backdoor-swift.ru/cmd",   "url",    "scenario",   "c2"),
    ("cobalt-strike-c2-bank.com",       "domain", "malwarebazaar","c2"),
    ("fin7-jssloader-c2.net",           "domain", "threatfox",  "c2"),
    ("https://dridex-c2.ru/bot/cmd",    "url",    "malwarebazaar","c2"),
    ("https://silence-group.ru/gate",   "url",    "otx",        "c2"),
]


# ── Feature engineering ─────────────────────────────────────────────────────

_IOC_TYPES = ["ip", "hash_md5", "hash_sha256", "domain", "url", "cve"]
_SOURCES   = ["otx", "urlhaus", "threatfox", "malwarebazaar", "misp", "scenario"]


class IOCFeatureExtractor(BaseEstimator, TransformerMixin):
    """Converts (value, type, source) tuples into a numeric feature matrix."""

    def fit(self, X, y=None):
        return self

    @staticmethod
    def _is_private_ip(value: str) -> bool:
        """True if value looks like a private/internal IP — strong lateral movement signal."""
        import re
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return False
        parts = value.split(".")
        try:
            a, b = int(parts[0]), int(parts[1])
        except ValueError:
            return False
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
        )

    def transform(self, X):
        rows = []
        for value, ioc_type, source in X:
            row = []
            # One-hot: IOC type
            row += [1 if ioc_type == t else 0 for t in _IOC_TYPES]
            # One-hot: source
            row += [1 if source == s else 0 for s in _SOURCES]
            # Value keyword features
            v = value.lower()
            row.append(1 if any(k in v for k in ["bank", "banque", "swift", "bct", "treasury", "payment", "atlas"]) else 0)
            row.append(1 if any(k in v for k in ["login", "secure", "verify", "auth", "portal", "update"]) else 0)
            row.append(1 if any(k in v for k in ["c2", "beacon", "gate", "cmd", "poll", "check", "pipe"]) else 0)
            row.append(1 if any(k in v for k in ["exfil", "dump", "recv", "drop", "upload", "data", "stealer"]) else 0)
            row.append(1 if any(k in v for k in ["lateral", "pivot", "mimikatz", "lsass", "psexec", "wmi", "rdp", "smb"]) else 0)
            row.append(1 if any(k in v for k in ["carbanak", "fin7", "lazarus", "silence", "cobalt", "trickbot", "emotet", "dridex"]) else 0)
            row.append(1 if any(k in v for k in [".ru", ".xyz", ".tk", ".ml", ".ga", ".cf", ".onion"]) else 0)
            row.append(1 if ioc_type in ("hash_md5", "hash_sha256") else 0)
            row.append(1 if ioc_type == "cve" else 0)
            row.append(1 if ioc_type == "url" else 0)
            # Private IP feature — direct signal for lateral movement
            row.append(1 if self._is_private_ip(value) else 0)
            rows.append(row)
        return np.array(rows, dtype=float)


# ── Train / load ────────────────────────────────────────────────────────────

_model: Optional[LogisticRegression] = None
_label_encoder: Optional[LabelEncoder] = None


def _train_and_save() -> tuple:
    """Train on the built-in labeled dataset and persist to disk."""
    X = [(v, t, s) for v, t, s, _ in _TRAINING_DATA]
    y = [label for _, _, _, label in _TRAINING_DATA]

    extractor = IOCFeatureExtractor()
    X_feat = extractor.fit_transform(X)

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    clf = LogisticRegression(max_iter=500, random_state=42)
    clf.fit(X_feat, y_enc)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"clf": clf, "le": le, "extractor": extractor}, f)

    return clf, le, extractor


def _load_model():
    global _model, _label_encoder, _extractor
    if MODEL_PATH.exists():
        with open(MODEL_PATH, "rb") as f:
            bundle = pickle.load(f)
        _model       = bundle["clf"]
        _label_encoder = bundle["le"]
        _extractor   = bundle["extractor"]
    else:
        _model, _label_encoder, _extractor = _train_and_save()


_extractor: Optional[IOCFeatureExtractor] = None


def classify(value: str, ioc_type: str, source: str) -> str:
    """
    Predict threat type for a single IOC.
    Returns one of: phishing | malware | lateral_movement | exfiltration | c2
    Loads (or trains) the model lazily on first call.
    """
    if _model is None:
        _load_model()
    feat = _extractor.transform([(value, ioc_type, source)])
    pred = _model.predict(feat)[0]
    return _label_encoder.inverse_transform([pred])[0]


def train(force: bool = False) -> None:
    """Explicitly train and save the model. Use force=True to retrain."""
    global _model, _label_encoder, _extractor
    if force or not MODEL_PATH.exists():
        _model, _label_encoder, _extractor = _train_and_save()
        print(f"Model trained on {len(_TRAINING_DATA)} samples -> {MODEL_PATH}")
    else:
        print(f"Model already exists at {MODEL_PATH}. Use force=True to retrain.")


if __name__ == "__main__":
    train(force=True)
    # Quick smoke-test
    tests = [
        ("secure-bctonline.com",    "domain",     "urlhaus"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash_md5", "malwarebazaar"),
        ("c2.lazarus-update.net",   "domain",     "threatfox"),
        ("185.220.101.45",          "ip",         "otx"),
        ("10.0.5.22",               "ip",         "scenario"),
        ("CVE-2021-44228",          "cve",        "otx"),
    ]
    print("\nSmoke test:")
    for v, t, s in tests:
        print(f"  {t:12} {v:45} -> {classify(v, t, s)}")
