#!/usr/bin/env python3
"""
Email Risk Analyzer
===================
Scans raw RFC-822 emails (.eml) for phishing indicators and spoofing signs,
assigns a 0-100 risk score, and produces an email security audit report (PDF).

Pipeline
--------
 1. Parse raw headers      : From / Return-Path / Reply-To, Received chain,
                             SPF / DKIM / DMARC results, Message-ID, Date
 2. Scan the body          : links (href vs. visible text), lookalike domains,
                             urgent / threatening / credential lure language,
                             HTML password forms, risky attachments
 3. Score                  : weighted sum of findings, capped at 100
 4. Report                 : console summary, optional JSON, optional PDF

Usage
-----
    python email_analyzer.py message.eml [more.eml ...] --pdf report.pdf
    python email_analyzer.py --demo                 # builds samples + report
    cat message.eml | python email_analyzer.py -    # read from stdin

Dependencies: Python 3.9+ standard library only. The PDF report additionally
needs `reportlab` (pip install reportlab).

This is a heuristic, offline, defensive tool. It performs no network lookups
and never fetches or opens any URL found in an email.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #

# Brands commonly impersonated, with their legitimate registered domains.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com",
                  "microsoftonline.com", "office365.com", "msn.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "facebookmail.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "whatsapp": {"whatsapp.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "github": {"github.com", "githubusercontent.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "sbi": {"sbi.co.in", "onlinesbi.com", "onlinesbi.sbi", "sbi.bank.in"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com"},
    "paytm": {"paytm.com"},
}
ALL_OFFICIAL = set().union(*BRANDS.values())
BRAND_ALIASES = {"state bank of india": "sbi", "hdfc bank": "hdfc", "icici bank": "icici"}

FREE_MAIL = {"gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
             "proton.me", "protonmail.com", "aol.com", "icloud.com", "rediffmail.com",
             "gmx.com", "mail.com"}

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "mov",
                   "work", "support", "country", "kim", "loan", "icu", "buzz", "rest",
                   "cyou", "monster", "download", "stream"}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"}

MULTI_PART_TLDS = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.in", "net.in",
                   "org.in", "gov.in", "ac.in", "co.jp", "com.br", "co.nz", "co.za",
                   "com.cn", "com.sg"}

DANGEROUS_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "com", "pif",
                 "jar", "msi", "ps1", "hta", "lnk", "iso", "img", "wsf", "dll", "reg"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab"}
HTML_EXT = {"html", "htm", "shtml", "xhtml"}
DOUBLE_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv)\.(exe|scr|js|vbs|bat|cmd|com|lnk|jar|hta)$",
    re.I)

# Lure language: category -> (regex list, base points, extra points per additional
# distinct hit, cap).
LURES: dict[str, dict] = {
    "Urgency": dict(base=5, extra=3, cap=14, patterns=[
        r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bact now\b",
        r"\bwithin \d+ hours?\b", r"\bfinal (notice|warning)\b", r"\blast chance\b",
        r"\bexpires? (today|soon|in)\b", r"\bas soon as possible\b", r"\bright away\b",
        r"\btime[- ]sensitive\b", r"\bexpired\b"]),
    "Threat / fear": dict(base=8, extra=4, cap=18, patterns=[
        r"\baccount (will be |has been |is )?(suspended|locked|closed|terminated|disabled|limited|blocked)\b",
        r"\bwill be (suspended|blocked|closed|terminated|deactivated)\b",
        r"\bunauthori[sz]ed (access|activity|login|transaction)\b",
        r"\bsuspicious (activity|sign[- ]?in|login)\b", r"\blegal action\b",
        r"\bpermanently (closed|deleted|disabled)\b"]),
    "Credential harvesting": dict(base=8, extra=4, cap=20, patterns=[
        r"\bverify your (account|identity|password|email|information|details)\b",
        r"\bconfirm your (account|identity|password|details|information)\b",
        r"\bupdate your (payment|billing|account|password|information|kyc)\b",
        r"\bre-?activate\b", r"\blog ?in (now|here)\b", r"\bpassword (will )?expire",
        r"\b(otp|one[- ]time password|cvv|aadhaar|pan card|pan number)\b",
        r"\bshare your\b"]),
    "Financial lure": dict(base=4, extra=2, cap=10, patterns=[
        r"\bwire transfer\b", r"\bgift cards?\b", r"\bpayment (failed|declined|overdue|pending)\b",
        r"\binvoice\b", r"\brefund\b", r"\bbank (details|account)\b", r"\bkyc\b",
        r"\bnew vendor\b"]),
    "Reward / prize": dict(base=8, extra=3, cap=14, patterns=[
        r"\byou(?:'ve| have) won\b", r"\bcongratulations\b",
        r"\bclaim your (prize|reward|gift)\b", r"\blottery\b", r"\bfree gift\b"]),
    "Impersonation / BEC": dict(base=8, extra=4, cap=14, patterns=[
        r"\bare you available\b", r"\bkeep (this|it) (confidential|discreet|between us)\b",
        r"\b(can'?t|cannot) (take|answer) (calls?|phone)\b", r"\bin a meeting\b",
        r"\bquick (task|favou?r)\b", r"\bsent from my (iphone|ipad|mobile)\b"]),
    "Generic greeting": dict(base=4, extra=0, cap=4, patterns=[
        r"\bdear (customer|user|client|member|account holder|valued customer|sir ?/? ?madam)\b"]),
}

BANDS = [  # (min score, label, meaning)
    (0, "LOW", "Likely legitimate"),
    (20, "MEDIUM", "Suspicious - manual review advised"),
    (45, "HIGH", "Likely phishing / spoofed"),
    (70, "CRITICAL", "Phishing or spoofing - do not interact"),
]


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def registered_domain(host: str) -> str:
    """Heuristic eTLD+1 (no public-suffix list, so offline & dependency-free)."""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip("<> ").lower() if "@" in addr else ""


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_HOMOGLYPH_L = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"})
_HOMOGLYPH_I = str.maketrans({"0": "o", "1": "i", "3": "e", "5": "s", "$": "s", "@": "a"})


def homoglyph_variants(label: str) -> set[str]:
    out = set()
    for table in (_HOMOGLYPH_L, _HOMOGLYPH_I):
        v = label.translate(table).replace("rn", "m").replace("vv", "w")
        if v != label:
            out.add(v)
    return out


def is_internal_ip(ip: str) -> bool:
    """Loopback / RFC1918 / link-local. (Documentation ranges count as external.)"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    nets = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"]
    return any(a in ipaddress.ip_network(n) for n in nets)


def defang(url: str, limit: int = 110) -> str:
    """Make a URL safe to print/click: hxxp + [.] notation."""
    s = re.sub(r"^http", "hxxp", url, flags=re.I).replace(".", "[.]")
    return s if len(s) <= limit else s[: limit - 3] + "..."


def severity_for(points: int) -> str:
    if points >= 20:
        return "critical"
    if points >= 12:
        return "high"
    if points >= 6:
        return "medium"
    return "low" if points >= 1 else "info"


def band_for(score: int) -> tuple[str, str]:
    label, meaning = BANDS[0][1], BANDS[0][2]
    for threshold, lab, mean in BANDS:
        if score >= threshold:
            label, meaning = lab, mean
    return label, meaning


def domain_issues(host: str) -> list[tuple[str, str, int]]:
    """Return [(title, detail, points)] describing spoofing signs in a hostname."""
    issues: list[tuple[str, str, int]] = []
    host = host.lower().strip(".")
    if not host:
        return issues
    reg = registered_domain(host)
    if reg in ALL_OFFICIAL:
        return issues
    label = reg.split(".")[0]
    tld = host.rsplit(".", 1)[-1]

    if any(p.startswith("xn--") for p in host.split(".")) or any(ord(c) > 127 for c in host):
        issues.append(("Punycode / non-ASCII domain",
                       f"'{host}' uses IDN characters - a common homograph spoofing trick.", 15))
    if tld in SUSPICIOUS_TLDS:
        issues.append(("High-abuse top-level domain",
                       f"'.{tld}' is heavily used for throw-away phishing domains.", 8))

    sub = host[: -(len(reg) + 1)] if host != reg else ""
    hit = False
    for brand, official in BRANDS.items():
        # Brand (or its real domain) used as a subdomain of an unrelated domain.
        if sub and (any(o in sub for o in official) or (len(brand) >= 5 and brand in sub)):
            issues.append(("Brand name used in subdomain of unrelated domain",
                           f"'{host}' puts '{brand}' in front of the real domain '{reg}'.", 18))
            hit = True
            break
    if not hit:
        for brand, official in BRANDS.items():
            tokens = re.split(r"[-_.]", label)
            if brand in tokens or (len(brand) >= 5 and brand in label):
                issues.append(("Brand name embedded in unrelated domain",
                               f"'{reg}' contains '{brand}' but is not an official {brand} domain.", 20))
                break
            hom = [v for v in homoglyph_variants(label)
                   if brand in re.split(r"[-_.]", v) or (len(brand) >= 5 and brand in v)]
            if hom:
                issues.append(("Homoglyph / look-alike domain",
                               f"'{reg}' imitates '{brand}' using look-alike characters.", 25))
                break
            if len(brand) >= 5 and 0 < levenshtein(label, brand) <= 2:
                issues.append(("Typosquatted domain",
                               f"'{reg}' is 1-2 characters away from '{brand}'.", 22))
                break
    return issues


# --------------------------------------------------------------------------- #
# HTML scanning
# --------------------------------------------------------------------------- #

class _HTMLScan(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[dict] = []
        self.forms: list[str] = []
        self.password_field = False
        self._cur: dict | None = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a" and a.get("href"):
            self._cur = {"href": a["href"].strip(), "text": ""}
        elif tag == "form":
            self.forms.append((a.get("action") or "").strip())
        elif tag == "input" and (a.get("type") or "").lower() == "password":
            self.password_field = True

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._cur is not None:
            self.links.append(self._cur)
            self._cur = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._cur is not None:
            self._cur["text"] += data


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    category: str      # Header | Authentication | Routing | Link | Content | Attachment
    severity: str      # info | low | medium | high | critical
    title: str
    detail: str
    points: int
    evidence: str = ""


@dataclass
class Result:
    source: str
    summary: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    links: list = field(default_factory=list)
    score: int = 0
    band: str = "LOW"
    verdict: str = ""


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #

class EmailAnalyzer:
    def __init__(self, raw: bytes, source: str = "<stdin>") -> None:
        self.msg = BytesParser(policy=policy.default).parsebytes(raw)
        self.source = source
        self.findings: list[Finding] = []
        self.summary: dict = {}
        self._seen: set = set()

    # -- utilities ---------------------------------------------------------- #
    def add(self, category: str, title: str, detail: str, points: int, evidence: str = "") -> None:
        key = (category, title, evidence)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(category, severity_for(points), title, detail, points, evidence))

    def _hdr(self, name: str) -> str:
        v = self.msg.get(name)
        return str(v).strip() if v is not None else ""

    # -- 1. sender / identity headers -------------------------------------- #
    def check_sender_headers(self) -> None:
        from_all = self.msg.get_all("From", [])
        name, addr = parseaddr(str(from_all[0])) if from_all else ("", "")
        from_dom = domain_of(addr)
        from_reg = registered_domain(from_dom) if from_dom else ""
        rp_addr = parseaddr(self._hdr("Return-Path"))[1]
        rp_dom = domain_of(rp_addr)
        reply_addrs = [parseaddr(x)[1] for x in re.split(r",(?![^<]*>)", self._hdr("Reply-To")) if x.strip()]
        reply_doms = sorted({domain_of(a) for a in reply_addrs if a})

        self.summary.update({
            "subject": self._hdr("Subject"), "from": self._hdr("From"), "from_domain": from_dom,
            "return_path": self._hdr("Return-Path"), "reply_to": self._hdr("Reply-To"),
            "to": self._hdr("To"), "date": self._hdr("Date"), "message_id": self._hdr("Message-ID"),
        })

        if not from_all:
            self.add("Header", "Missing From header", "Message has no From header.", 15)
        if len(from_all) > 1:
            self.add("Header", "Multiple From headers",
                     "Duplicate From headers are used to confuse mail clients and filters.", 12)

        # Sender domain spoofing signs
        for title, detail, pts in domain_issues(from_dom):
            self.add("Header", f"Sender domain: {title}", detail, pts, from_dom)

        # Return-Path vs From
        if rp_dom and from_reg and registered_domain(rp_dom) != from_reg:
            self.add("Header", "Return-Path domain differs from From domain",
                     f"Envelope sender is '{rp_dom}' but the visible sender is '{from_dom}'. "
                     "Legitimate bulk senders do this too, but it is a classic spoofing signal.",
                     8, f"From={from_dom}  Return-Path={rp_dom}")
            for title, detail, pts in domain_issues(rp_dom):
                self.add("Header", f"Return-Path domain: {title}", detail, min(pts, 8), rp_dom)

        # Reply-To redirection
        for d in reply_doms:
            if from_reg and registered_domain(d) != from_reg:
                self.add("Header", "Reply-To points to a different domain",
                         "Replies are silently redirected away from the apparent sender.",
                         12, f"From={from_dom}  Reply-To={d}")

        # Display-name tricks
        lname = name.lower()
        m = re.search(r"[\w.+-]+@([\w.-]+\.\w+)", name)
        if m and from_reg and registered_domain(m.group(1)) != from_reg:
            self.add("Header", "Display name embeds a different e-mail address",
                     "Mail apps often show only the display name, hiding the real address.",
                     20, f'Display name "{name}"')
        for alias, brand in BRAND_ALIASES.items():
            lname = lname.replace(alias, brand)
        for brand, official in BRANDS.items():
            if re.search(rf"\b{re.escape(brand)}\b", lname) and from_reg and from_reg not in official:
                self.add("Header", "Display name impersonates a known brand",
                         f"Display name mentions '{brand}' but the address domain is '{from_reg}'.",
                         18, f'Display name "{name}"')
                break
        if from_reg in FREE_MAIL and re.search(
                r"\b(ceo|cfo|coo|director|president|managing|hr|helpdesk|help desk|support|"
                r"admin|security|payroll|accounts?)\b", lname):
            self.add("Header", "Authority/role name sent from a free-mail account",
                     "Executives and support teams rarely write from public webmail; typical of "
                     "business-e-mail-compromise (BEC) fraud.", 15, f'"{name}" <{addr}>')

        # Message-ID sanity
        mid = self._hdr("Message-ID")
        if not mid:
            self.add("Header", "Missing Message-ID", "Most legitimate MTAs always add a Message-ID.", 5)
        else:
            mdom = domain_of(mid.strip("<>"))
            if mdom and from_reg and registered_domain(mdom) != from_reg:
                self.add("Header", "Message-ID domain differs from sender domain",
                         "Mild signal on its own (many ESPs do this).", 3, mid)
        if not self._hdr("Date"):
            self.add("Header", "Missing Date header", "Forged or hand-built messages often omit Date.", 4)

    # -- 2. SPF / DKIM / DMARC --------------------------------------------- #
    def check_authentication(self) -> None:
        res: dict[str, str | None] = {"spf": None, "dkim": None, "dmarc": None}
        for h in self.msg.get_all("Authentication-Results", []):
            for mech in res:
                m = re.search(rf"\b{mech}\s*=\s*(\w+)", str(h), re.I)
                if m and res[mech] is None:   # first (= most recent) header wins
                    res[mech] = m.group(1).lower()
        rspf = self._hdr("Received-SPF")
        if res["spf"] is None and rspf:
            res["spf"] = rspf.split()[0].lower()

        dkim_domains = []
        for sig in self.msg.get_all("DKIM-Signature", []):
            m = re.search(r"\bd=([^;\s]+)", str(sig))
            if m:
                dkim_domains.append(m.group(1).lower())
        self.summary.update({"spf": res["spf"], "dkim": res["dkim"], "dmarc": res["dmarc"],
                             "dkim_domains": dkim_domains})

        if not any(res.values()) and not dkim_domains:
            self.add("Authentication", "No SPF/DKIM/DMARC results present",
                     "The message carries no authentication evidence, so the sender cannot be verified.", 8)
        else:
            spf_pts = {"fail": 20, "softfail": 10, "none": 6, "neutral": 6,
                       "permerror": 5, "temperror": 5}
            dkim_pts = {"fail": 18, "none": 6, "neutral": 6, "policy": 6,
                        "permerror": 5, "temperror": 5}
            dmarc_pts = {"fail": 20, "none": 5, "permerror": 5, "temperror": 4}
            for mech, table, label in (("spf", spf_pts, "SPF"), ("dkim", dkim_pts, "DKIM"),
                                       ("dmarc", dmarc_pts, "DMARC")):
                val = res[mech]
                if val is None:
                    continue
                pts = table.get(val, 0)
                if pts:
                    self.add("Authentication", f"{label} result: {val}",
                             f"{label} did not validate ({val}); the sending server is not proven "
                             "to be authorised for this domain." if mech != "dkim" else
                             f"DKIM signature check returned '{val}'.", pts, f"{label.lower()}={val}")
                else:
                    self.add("Authentication", f"{label} result: {val}", f"{label} validated.", 0,
                             f"{label.lower()}={val}")

        from_reg = registered_domain(self.summary.get("from_domain", "") or "")
        for d in dkim_domains:
            if from_reg and registered_domain(d) != from_reg:
                self.add("Authentication", "DKIM signing domain not aligned with From domain",
                         f"Message is signed by '{d}', not by the visible sender '{from_reg}'. "
                         "Attackers can sign with a domain they own.", 8, f"d={d}")

    # -- 3. Received chain -------------------------------------------------- #
    def check_received_chain(self) -> None:
        hops = []
        for r in self.msg.get_all("Received", []):
            r = " ".join(str(r).split())
            ts = None
            if ";" in r:
                try:
                    ts = parsedate_to_datetime(r.rsplit(";", 1)[1].strip())
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                except (TypeError, ValueError):
                    ts = None
            frm = re.search(r"\bfrom\s+(\S+)", r, re.I)
            by = re.search(r"\bby\s+(\S+)", r, re.I)
            rdns = re.search(r"\bfrom\s+\S+\s+\(([^\s\[\)]+)", r, re.I)
            ips = re.findall(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", r)
            hops.append({"from": frm.group(1) if frm else "", "by": by.group(1) if by else "",
                         "rdns": rdns.group(1) if rdns else "", "ips": ips, "time": ts})

        origin_ip = ""
        for h in reversed(hops):                    # oldest hop first
            ext = [i for i in h["ips"] if not is_internal_ip(i)]
            if ext:
                origin_ip = ext[0]
                break
        self.summary.update({
            "hop_count": len(hops),
            "origin_ip": origin_ip,
            "origin_helo": hops[-1]["from"] if hops else "",
            "hops": [{"from": h["from"], "by": h["by"], "ips": h["ips"],
                      "time": h["time"].isoformat() if h["time"] else ""} for h in hops],
        })

        if not hops:
            self.add("Routing", "No Received headers",
                     "A delivered message always has at least one Received hop; "
                     "its absence suggests a crafted or locally injected file.", 8)
            return

        origin = hops[-1]
        helo = origin["from"].strip("[]").lower()
        if helo in ("localhost", "unknown", "") or ("." not in helo and not helo.startswith("[")):
            self.add("Routing", "Origin hop uses a generic / non-FQDN HELO name",
                     f"First hop identifies itself as '{origin['from'] or 'n/a'}', typical of "
                     "scripted mailers rather than real mail servers.", 5, origin["from"])

        for h in hops:
            helo_n, rdns = h["from"].lower(), h["rdns"].lower()
            if "." in helo_n and "." in rdns and not re.match(r"^[\d.]+$", rdns) \
                    and registered_domain(helo_n) != registered_domain(rdns):
                self.add("Routing", "HELO name does not match reverse DNS",
                         f"Server announced '{helo_n}' but resolves as '{rdns}'.", 8, f"{helo_n} / {rdns}")

        stamped = [h for h in hops if h["time"]]
        for newer, older in zip(stamped, stamped[1:]):
            if (older["time"] - newer["time"]).total_seconds() > 300:
                self.add("Routing", "Received timestamps are out of order",
                         "A later hop is stamped earlier than the hop before it - "
                         "evidence of forged or badly skewed headers.", 8,
                         f"{older['time']:%Y-%m-%d %H:%M} > {newer['time']:%Y-%m-%d %H:%M}")
                break
        try:
            sent = parsedate_to_datetime(self._hdr("Date"))
            if sent.tzinfo is None:
                sent = sent.replace(tzinfo=timezone.utc)
            first_seen = (stamped[-1]["time"] if stamped else None)
            if first_seen and abs((first_seen - sent).total_seconds()) > 2 * 86400:
                self.add("Routing", "Date header far from first-hop timestamp",
                         "Date header and the first server hop disagree by more than 2 days.", 5,
                         f"Date={sent:%Y-%m-%d}  hop={first_seen:%Y-%m-%d}")
        except (TypeError, ValueError):
            pass
        if len(hops) > 10:
            self.add("Routing", "Unusually long relay chain", f"{len(hops)} hops.", 3)

    # -- 4. Body, links, forms, content ------------------------------------ #
    def _bodies(self) -> tuple[str, str]:
        plain, html = [], []
        for part in self.msg.walk():
            if part.is_multipart() or part.get_content_disposition() == "attachment":
                continue
            ctype = part.get_content_type()
            if ctype not in ("text/plain", "text/html"):
                continue
            try:
                content = part.get_content()
            except Exception:  # noqa: BLE001 - malformed charset etc.
                payload = part.get_payload(decode=True) or b""
                content = payload.decode("utf-8", "replace")
            (html if ctype == "text/html" else plain).append(content)
        return "\n".join(plain), "\n".join(html)

    def check_links(self, plain: str, scan: _HTMLScan) -> list[dict]:
        links = list(scan.links)
        known = {l["href"] for l in links}
        for url in re.findall(r"https?://[^\s<>\"')\]]+", plain + " " + " ".join(scan.text)):
            url = url.rstrip(".,;")
            if url not in known:
                links.append({"href": url, "text": ""})
                known.add(url)

        sender_reg = registered_domain(self.summary.get("from_domain", "") or "")
        out = []
        for l in links:
            href, text = l["href"], " ".join(l["text"].split())
            flags: list[str] = []
            try:
                p = urlparse(href)
            except ValueError:
                continue
            scheme = p.scheme.lower()
            if scheme in ("javascript", "data", "vbscript"):
                self.add("Link", "Dangerous URL scheme", f"'{scheme}:' links can run code or hide content.",
                         20, href[:60])
                flags.append("dangerous scheme")
                out.append({"url": href, "text": text, "host": "", "flags": flags})
                continue
            if scheme not in ("http", "https"):
                continue
            host = (p.hostname or "").lower()
            ev = defang(href)

            def flag(title, detail, pts, f=flags, ev=ev):
                self.add("Link", title, detail, pts, ev)
                f.append(title)

            if "@" in p.netloc:
                flag("URL contains user@host trick",
                     "Everything before '@' is ignored by the browser and used to disguise the real host.", 20)
            is_ip = False
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                if re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host):
                    is_ip = True
            if is_ip:
                flag("Link points to a raw IP address",
                     "Legitimate brands link to named domains, not IP addresses.", 20)
            else:
                if host in SHORTENERS or registered_domain(host) in SHORTENERS:
                    flag("URL shortener hides the destination",
                         "Short links prevent inspection of where the click really leads.", 8)
                for title, detail, pts in domain_issues(host):
                    flag(f"Link domain: {title}", detail, pts)
                if host.count(".") >= 4:
                    flag("Excessive subdomain depth", f"'{host}' has {host.count('.') + 1} labels.", 6)
            if scheme == "http":
                flag("Unencrypted (http) link", "Credentials entered here would travel in clear text.", 5)
            if re.search(r"[?&](url|redirect|redir|next|target|dest|goto|link|u)=(https?(%3a|:))",
                         href, re.I):
                flag("Open-redirect style parameter",
                     "The URL embeds another URL, often used to launder a malicious destination.", 8)

            # Visible text vs real target
            m = re.search(r"((?:https?://)?(?:[\w-]+\.)+[a-z]{2,})(?:/\S*)?", text, re.I)
            if m and host:
                shown = m.group(1)
                shown_host = (urlparse(shown if "://" in shown else "http://" + shown).hostname or "")
                if shown_host and registered_domain(shown_host) != registered_domain(host):
                    flag("Link text shows one domain but points to another",
                         f"Reader sees '{shown_host}' but the click goes to '{host}'.", 25)
            out.append({"url": href, "text": text, "host": host, "flags": flags})
        self.summary["link_count"] = len(out)
        return out

    def check_forms(self, scan: _HTMLScan) -> None:
        sender_reg = registered_domain(self.summary.get("from_domain", "") or "")
        if scan.password_field:
            self.add("Content", "Password field embedded in the e-mail",
                     "Real services never ask for passwords inside an e-mail body.", 20)
        for action in scan.forms:
            host = urlparse(action).hostname or ""
            if host and registered_domain(host) != sender_reg:
                self.add("Content", "Embedded form submits to an external host",
                         "Form data is posted to a server that is not the sender's domain.", 10,
                         defang(action))

    def check_content(self, subject: str, body: str) -> None:
        text = f"{subject}\n{body}".lower()
        hit_categories = []
        for cat, cfg in LURES.items():
            matched = []
            for pat in cfg["patterns"]:
                m = re.search(pat, text)
                if m:
                    matched.append(m.group(0))
            if not matched:
                continue
            pts = min(cfg["cap"], cfg["base"] + cfg["extra"] * (len(matched) - 1))
            hit_categories.append(cat)
            self.add("Content", f"{cat} language",
                     f"{len(matched)} distinct indicator(s) found.", pts,
                     "; ".join(f'"{x}"' for x in matched[:5]))
        core = {"Urgency", "Threat / fear", "Credential harvesting"}
        if len(core.intersection(hit_categories)) >= 3:
            self.add("Content", "Classic phishing combination",
                     "Urgency + threat + credential request together is the signature pattern of "
                     "account-takeover phishing.", 8)
        if text.count("!") >= 3:
            self.add("Content", "Excessive exclamation marks", "Pressure tactic.", 3)

    def check_attachments(self) -> None:
        names = []
        for part in self.msg.walk():
            fn = part.get_filename()
            if not fn:
                continue
            names.append(fn)
            ext = fn.lower().rsplit(".", 1)[-1] if "." in fn else ""
            if DOUBLE_EXT.search(fn):
                self.add("Attachment", "Double file extension", "Disguises an executable as a document.", 25, fn)
            elif ext in DANGEROUS_EXT:
                self.add("Attachment", "Executable / script attachment", f"'.{ext}' can run code.", 20, fn)
            elif ext in MACRO_EXT:
                self.add("Attachment", "Macro-enabled Office attachment", "Common malware dropper.", 15, fn)
            elif ext in HTML_EXT:
                self.add("Attachment", "HTML attachment", "Often a local credential-harvesting page.", 12, fn)
            elif ext in ARCHIVE_EXT:
                self.add("Attachment", "Archive attachment", "Archives are used to bypass scanners.", 6, fn)
        self.summary["attachments"] = names

    # -- orchestration ------------------------------------------------------ #
    def analyze(self) -> Result:
        self.check_sender_headers()
        self.check_authentication()
        self.check_received_chain()
        plain, html = self._bodies()
        scan = _HTMLScan()
        if html:
            scan.feed(html)
        links = self.check_links(plain, scan)
        self.check_forms(scan)
        self.check_content(self.summary.get("subject", ""), plain + " " + " ".join(scan.text))
        self.check_attachments()

        findings = sorted(self.findings, key=lambda f: -f.points)
        score = min(100, sum(f.points for f in findings))
        band, meaning = band_for(score)
        return Result(self.source, self.summary, findings, links, score, band, meaning)


def analyze_file(path: str) -> Result:
    raw = sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()
    return EmailAnalyzer(raw, "<stdin>" if path == "-" else Path(path).name).analyze()


# --------------------------------------------------------------------------- #
# Console output
# --------------------------------------------------------------------------- #

def print_result(r: Result) -> None:
    s = r.summary
    bar = "#" * (r.score // 5) + "." * (20 - r.score // 5)
    print("=" * 78)
    print(f"File    : {r.source}")
    print(f"From    : {s.get('from')}")
    print(f"Subject : {s.get('subject')}")
    print(f"Auth    : SPF={s.get('spf')}  DKIM={s.get('dkim')}  DMARC={s.get('dmarc')}   "
          f"hops={s.get('hop_count')}  origin={s.get('origin_ip') or 'n/a'}")
    print(f"RISK    : [{bar}] {r.score}/100  {r.band} - {r.verdict}")
    print("-" * 78)
    for f in r.findings:
        if f.points == 0:
            continue
        print(f"  +{f.points:<3} {f.severity.upper():<8} [{f.category}] {f.title}")
        if f.evidence:
            print(f"        evidence: {f.evidence[:100]}")
    print()


# --------------------------------------------------------------------------- #
# Built-in sample messages (synthetic; documentation IP ranges, fake domains)
# --------------------------------------------------------------------------- #

def _b64(data: bytes) -> str:
    return base64.encodebytes(data).decode()


def sample_emails() -> dict[str, str]:
    phish_html = (
        "<html><body>\n<p>Dear Customer,</p>\n"
        "<p>We detected <b>unauthorized access</b> to your account. Your account has been suspended. "
        "You must verify your account immediately or it will be permanently closed within 24 hours.</p>\n"
        '<p><a href="http://paypal.com.account-verify.top/signin?redirect=http://203.0.113.45/collect">'
        "https://www.paypal.com/myaccount/verify</a></p>\n"
        '<p>Update your payment details: <a href="http://203.0.113.45/update.php">Update Now</a></p>\n'
        '<p>Quick link: <a href="https://bit.ly/3xYz123">https://bit.ly/3xYz123</a></p>\n'
        '<form action="http://203.0.113.45/login.php"><input type="text" name="email">'
        '<input type="password" name="pw"></form>\n'
        "<p>PayPal Security Team</p>\n</body></html>\n")

    paypal = f"""Received: from mail-gw.paypa1-secure-login.com (unknown [203.0.113.45])
\tby mx.example-mail.net (Postfix) with ESMTP id 4F2A1; Mon, 05 Oct 2026 03:12:44 +0000
Received: from localhost (localhost [127.0.0.1])
\tby mail-gw.paypa1-secure-login.com (Postfix) with ESMTP id 9C1; Sun, 04 Oct 2026 21:58:10 +0000
Authentication-Results: mx.example-mail.net;
\tspf=fail (203.0.113.45 is not a permitted sender) smtp.mailfrom=bounce@mailer.bulk-sender.top;
\tdkim=none; dmarc=fail (p=none) header.from=paypa1-secure-login.com
Return-Path: <bounce@mailer.bulk-sender.top>
From: "PayPal Support" <security-alert@paypa1-secure-login.com>
Reply-To: <recovery.desk@gmail.com>
To: student@example-mail.net
Subject: URGENT: Your account has been suspended - verify within 24 hours!
Date: Mon, 05 Oct 2026 03:12:40 +0000
Message-ID: <a1b2c3@mail-gw.paypa1-secure-login.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY1"

--BOUNDARY1
Content-Type: text/html; charset="utf-8"

{phish_html}
--BOUNDARY1
Content-Type: application/octet-stream; name="Invoice_4471.pdf.exe"
Content-Disposition: attachment; filename="Invoice_4471.pdf.exe"
Content-Transfer-Encoding: base64

{_b64(b"DEMO-ONLY-NOT-A-REAL-EXECUTABLE")}
--BOUNDARY1--
"""

    ceo = """Received: from mail-qt1-f171.mail.example (mail-qt1-f171.mail.example [198.51.100.71])
\tby mx.example-corp.in with ESMTPS id 77aa; Mon, 05 Oct 2026 09:01:12 +0530
Authentication-Results: mx.example-corp.in;
\tspf=pass smtp.mailfrom=rahul.menon.ceo@gmail.com;
\tdkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20230601; h=from:to:subject; b=ZmFrZQ==
Return-Path: <rahul.menon.ceo@gmail.com>
From: "Rahul Menon - CEO" <rahul.menon.ceo@gmail.com>
Reply-To: "Rahul Menon" <r.menon.office@proton.me>
To: accounts@example-corp.in
Subject: Quick task - urgent
Date: Mon, 05 Oct 2026 09:01:05 +0530
Message-ID: <CAB12345@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi,

Are you available? I'm in a meeting and can't take calls. I need you to process an
urgent wire transfer to a new vendor immediately. After that, please buy 5 gift cards
worth Rs. 10,000 each and send me the codes. Keep this confidential until I'm back.

Reply with the details as soon as possible.

Sent from my iPhone
"""

    sbi = """Received: from unknown (unknown [198.51.100.23])
\tby mx.example-mail.net with SMTP id 11bb; Mon, 05 Oct 2026 06:40:02 +0000
Authentication-Results: mx.example-mail.net;
\tspf=softfail smtp.mailfrom=alerts@sbi-kyc-update.xyz; dkim=none; dmarc=none
Return-Path: <alerts@sbi-kyc-update.xyz>
From: "SBI Alerts" <alerts@sbi-kyc-update.xyz>
To: student@example-mail.net
Subject: Final notice: KYC expired - account will be blocked today
Date: Mon, 05 Oct 2026 06:39:58 +0000
Message-ID: <77f@sbi-kyc-update.xyz>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Dear Customer,

Your State Bank of India YONO account KYC has expired. Your account will be blocked today.
Update your KYC immediately: http://onlinesbi.com.kyc-update.xyz/login

You must share your OTP and PAN card number on the page to re-activate. Last chance!!!
"""

    legit = """Received: from out-1.mailer.example (out-1.mailer.example [192.0.2.10])
\tby mx.example-mail.net with ESMTPS id 5ee; Mon, 05 Oct 2026 04:00:03 +0000
Received: from app-7.internal.example (app-7.internal.example [10.20.0.7])
\tby out-1.mailer.example with ESMTP id 5ee; Mon, 05 Oct 2026 04:00:01 +0000
Authentication-Results: mx.example-mail.net;
\tspf=pass smtp.mailfrom=notifications@github.com;
\tdkim=pass header.d=github.com; dmarc=pass header.from=github.com
DKIM-Signature: v=1; a=rsa-sha256; d=github.com; s=pf2023; h=from:to:subject; b=ZmFrZQ==
Return-Path: <notifications@github.com>
From: GitHub <notifications@github.com>
To: student@example-mail.net
Subject: [GitHub] Your weekly digest
Date: Mon, 05 Oct 2026 04:00:00 +0000
Message-ID: <digest-8841@github.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="ALT"

--ALT
Content-Type: text/plain; charset="utf-8"

Here is a summary of activity in your repositories this week.
View the repository: https://github.com/example-org/portfolio-site
--ALT
Content-Type: text/html; charset="utf-8"

<html><body><p>Here is a summary of activity in your repositories this week.</p>
<p><a href="https://github.com/example-org/portfolio-site">View repository</a></p></body></html>
--ALT--
"""
    return {"01_phishing_paypal.eml": paypal, "02_ceo_fraud_bec.eml": ceo,
            "03_sbi_kyc_phish.eml": sbi, "04_legit_github_digest.eml": legit}


# --------------------------------------------------------------------------- #
# PDF audit report
# --------------------------------------------------------------------------- #

def build_pdf(results: list[Result], path: str) -> None:
    try:
        from reportlab.graphics.charts.barcharts import HorizontalBarChart
        from reportlab.graphics.shapes import Drawing
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                        Spacer, Table, TableStyle)
    except ImportError:
        sys.exit("PDF output needs reportlab:  pip install reportlab")
    from xml.sax.saxutils import escape as esc

    BAND_COL = {"LOW": colors.HexColor("#2e7d32"), "MEDIUM": colors.HexColor("#b8860b"),
                "HIGH": colors.HexColor("#e65100"), "CRITICAL": colors.HexColor("#b71c1c")}
    SEV_COL = {"critical": "#b71c1c", "high": "#e65100", "medium": "#b8860b",
               "low": "#455a64", "info": "#2e7d32"}
    NAVY = colors.HexColor("#1a2b4c")
    GRID = colors.HexColor("#c9d1dc")
    LIGHT = colors.HexColor("#f3f6fa")

    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontSize=15, textColor=NAVY, spaceBefore=6, spaceAfter=6)
    H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=11.5, textColor=NAVY, spaceBefore=8, spaceAfter=4)
    BODY = ParagraphStyle("B", parent=ss["BodyText"], fontSize=9.2, leading=12.5)
    CELL = ParagraphStyle("C", parent=BODY, fontSize=8, leading=10)
    MONO = ParagraphStyle("M", parent=CELL, fontName="Courier", fontSize=7, leading=8.5)
    TITLE = ParagraphStyle("T", parent=ss["Title"], fontSize=24, textColor=NAVY, alignment=0, spaceAfter=4)
    SUB = ParagraphStyle("S", parent=BODY, fontSize=11, textColor=colors.HexColor("#455a64"))

    def P(t, st=CELL):
        return Paragraph(t, st)

    W = A4[0] - 36 * mm

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#78909c"))
        canvas.drawString(18 * mm, 10 * mm, f"Email Risk Analyzer v{__version__} - Phishing Analysis Report")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=18 * mm,
                            title="Phishing Analysis Report", author="Email Risk Analyzer")
    story = []

    # ---- Cover / executive summary ---- #
    now = datetime.now().strftime("%d %B %Y, %H:%M")
    story += [Paragraph("Email Security Audit Report", TITLE),
              Paragraph("Phishing &amp; spoofing analysis of raw e-mail headers and body content", SUB),
              Spacer(1, 4),
              Paragraph(f"Generated {now} &nbsp;|&nbsp; Tool: email_analyzer.py v{__version__} "
                        f"&nbsp;|&nbsp; Messages analysed: {len(results)}", CELL),
              Spacer(1, 10), Paragraph("1. Executive summary", H1)]

    flagged = [r for r in results if r.score >= 45]
    story.append(Paragraph(
        f"{len(results)} messages were scanned. <b>{len(flagged)}</b> were classified HIGH or CRITICAL risk "
        f"(likely phishing or spoofing), <b>{sum(1 for r in results if r.band == 'MEDIUM')}</b> as MEDIUM, and "
        f"<b>{sum(1 for r in results if r.band == 'LOW')}</b> as LOW. The scoring combines header authentication "
        "(SPF / DKIM / DMARC), identity spoofing signals (From / Return-Path / Reply-To / display name), "
        "mail-routing anomalies (Received chain), link and domain analysis, lure language, and attachments.",
        BODY))
    story.append(Spacer(1, 6))

    rows = [[P("<b>#</b>"), P("<b>Message</b>"), P("<b>Sender domain</b>"), P("<b>Score</b>"), P("<b>Verdict</b>")]]
    for i, r in enumerate(results, 1):
        col = BAND_COL[r.band].hexval()[2:]
        rows.append([P(str(i)), P(esc(r.source)), P(esc(r.summary.get("from_domain") or "n/a")),
                     P(f"<b>{r.score}/100</b>"),
                     P(f'<font color="#{col}"><b>{r.band}</b></font> - {esc(r.verdict)}')])
    t = Table(rows, colWidths=[8 * mm, 54 * mm, 42 * mm, 18 * mm, W - 122 * mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.4, GRID),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    story += [t, Spacer(1, 10)]

    d = Drawing(W, 28 * mm + 9 * mm * len(results))
    ch = HorizontalBarChart()
    ch.x, ch.y, ch.width, ch.height = 120, 14, W - 160, 9 * mm * len(results) + 12 * mm
    ch.data = [[r.score for r in reversed(results)]]
    ch.categoryAxis.categoryNames = [r.source.rsplit(".", 1)[0][:26] for r in reversed(results)]
    ch.categoryAxis.labels.fontSize = 7.5
    ch.valueAxis.valueMin, ch.valueAxis.valueMax, ch.valueAxis.valueStep = 0, 100, 20
    ch.valueAxis.labels.fontSize = 7.5
    ch.bars.strokeColor = None
    ch.barLabelFormat = "%d"
    ch.barLabels.fontSize = 7.5
    ch.barLabels.nudge = 8
    for idx, r in enumerate(reversed(results)):
        ch.bars[(0, idx)].fillColor = BAND_COL[r.band]
    d.add(ch)
    story += [Paragraph("Risk score by message (0 = benign, 100 = certain phishing)", H2), d]

    # ---- Methodology ---- #
    story += [PageBreak(), Paragraph("2. Methodology", H1),
              Paragraph("Each message is parsed with Python's <font name='Courier'>email</font> library and "
                        "analysed in four stages. Every triggered check adds weighted points; the total is capped "
                        "at 100. No network lookups are made and no URLs are ever visited.", BODY),
              Spacer(1, 4)]
    meth = [[P("<b>Stage</b>"), P("<b>What is inspected</b>"), P("<b>Typical points</b>")],
            [P("Header parsing"), P("From vs Return-Path vs Reply-To domain alignment; display-name impersonation "
                                    "of brands or executives; free-mail senders; missing/odd Message-ID and Date; "
                                    "look-alike (homoglyph / typosquat) sender domains."), P("3 - 25")],
            [P("SPF / DKIM / DMARC"), P("Authentication-Results and Received-SPF values; DKIM d= domain alignment "
                                        "with the visible sender."), P("fail 18-20, softfail 10, none 5-6")],
            [P("Received chain"), P("Hop count, origin IP, generic HELO names, HELO vs reverse-DNS mismatch, "
                                    "out-of-order timestamps, Date skew."), P("3 - 8")],
            [P("Links and forms"), P("Link text vs real target, raw-IP hosts, user@host tricks, shorteners, "
                                     "brand-in-subdomain, punycode, abused TLDs, http links, password forms."),
             P("5 - 25")],
            [P("Lure language"), P("Urgency, threats, credential requests, financial/BEC phrasing, rewards, "
                                   "generic greetings; bonus for the urgency+threat+credential combination."),
             P("4 - 18 per category")],
            [P("Attachments"), P("Executables, double extensions, macro documents, HTML and archives."),
             P("6 - 25")]]
    t = Table(meth, colWidths=[30 * mm, W - 68 * mm, 38 * mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.4, GRID),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t, Spacer(1, 8), Paragraph("Risk bands", H2)]
    bands = [[P("<b>Score</b>"), P("<b>Band</b>"), P("<b>Meaning</b>")]]
    edges = [(0, 19), (20, 44), (45, 69), (70, 100)]
    for (lo, hi), (_, lab, mean) in zip(edges, BANDS):
        bands.append([P(f"{lo} - {hi}"), P(f'<font color="#{BAND_COL[lab].hexval()[2:]}"><b>{lab}</b></font>'),
                      P(mean)])
    t = Table(bands, colWidths=[24 * mm, 28 * mm, W - 52 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.4, GRID)]))
    story.append(t)

    # ---- Per-message findings ---- #
    story += [PageBreak(), Paragraph("3. Detailed findings", H1)]
    for i, r in enumerate(results, 1):
        s = r.summary
        col = BAND_COL[r.band].hexval()[2:]
        head = [Paragraph(f"3.{i} {esc(r.source)}", H2),
                Paragraph(f'Risk score <b>{r.score}/100</b> - <font color="#{col}"><b>{r.band}</b></font> '
                          f"({esc(r.verdict)})", BODY)]
        top = [f for f in r.findings if f.points][:3]
        if top:
            head.append(Paragraph("Main drivers: " + "; ".join(esc(f.title) for f in top) + ".", BODY))
        head.append(Spacer(1, 4))

        kv = [("From", s.get("from")), ("Return-Path", s.get("return_path")), ("Reply-To", s.get("reply_to")),
              ("Subject", s.get("subject")), ("SPF / DKIM / DMARC",
                                              f"{s.get('spf')} / {s.get('dkim')} / {s.get('dmarc')}"),
              ("DKIM signing domain(s)", ", ".join(s.get("dkim_domains") or []) or "none"),
              ("Relay hops / origin IP", f"{s.get('hop_count')} / {s.get('origin_ip') or 'n/a'}"),
              ("Attachments", ", ".join(s.get("attachments") or []) or "none")]
        kt = Table([[P(f"<b>{k}</b>"), P(esc(str(v or "-")))] for k, v in kv], colWidths=[40 * mm, W - 40 * mm])
        kt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, GRID), ("BACKGROUND", (0, 0), (0, -1), LIGHT),
                                ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(KeepTogether(head + [kt, Spacer(1, 6)]))

        fr = [[P("<b>Severity</b>"), P("<b>Category</b>"), P("<b>Finding</b>"), P("<b>Pts</b>")]]
        for f in r.findings:
            body = f"<b>{esc(f.title)}</b><br/>{esc(f.detail)}"
            if f.evidence:
                body += f"<br/><font name='Courier' size='7' color='#455a64'>{esc(f.evidence[:140])}</font>"
            fr.append([P(f'<font color="{SEV_COL[f.severity]}"><b>{f.severity.upper()}</b></font>'),
                       P(f.category), P(body), P(f"+{f.points}" if f.points else "0")])
        ft = Table(fr, colWidths=[18 * mm, 24 * mm, W - 54 * mm, 12 * mm], repeatRows=1)
        ft.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.4, GRID),
                                ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(ft)

        if r.links:
            story += [Spacer(1, 6), Paragraph("Extracted URLs (defanged - safe to read, not clickable)", H2)]
            lr = [[P("<b>URL</b>"), P("<b>Visible text</b>"), P("<b>Flags</b>")]]
            for l in r.links[:12]:
                lr.append([P(esc(defang(l["url"], 80)), MONO), P(esc(l["text"][:50]) or "-"),
                           P(esc("; ".join(l["flags"])) or "none")])
            lt = Table(lr, colWidths=[62 * mm, 40 * mm, W - 102 * mm], repeatRows=1)
            lt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.4, GRID),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            story.append(lt)
        story.append(PageBreak() if i < len(results) else Spacer(1, 6))

    # ---- Recommendations & limitations ---- #
    story += [Paragraph("4. Recommendations", H1)]
    recs = [
        ("Quarantine HIGH / CRITICAL messages", "Block or quarantine, do not open links or attachments, and report "
         "the sender domain and URLs to the security team and the impersonated brand."),
        ("Enforce sender authentication", "Publish SPF and DKIM for your own domains and move DMARC to "
         "p=quarantine, then p=reject, so spoofed mail claiming to be you is rejected."),
        ("Verify money requests out-of-band", "Payment, gift-card or bank-detail changes must be confirmed by a "
         "phone call to a known number - this defeats BEC fraud that passes SPF/DKIM from free-mail accounts."),
        ("Distrust display names", "Always inspect the real address and Reply-To; configure the mail client to "
         "show full sender addresses and tag external senders."),
        ("Harden accounts", "Use MFA / passkeys so a stolen password alone is not enough, and never type "
         "credentials or OTPs into pages reached from e-mail links."),
        ("Contain attachments and links", "Sandbox or strip executables, macro documents and HTML attachments; "
         "rewrite and detonate URLs at the gateway."),
        ("Train and make reporting easy", "Run phishing simulations and provide a one-click 'Report phishing' "
         "button.")]
    story += [Paragraph(f"<b>{i}. {esc(h)}.</b> {esc(t)}", BODY) for i, (h, t) in enumerate(recs, 1)]
    story += [Spacer(1, 8), Paragraph("5. Limitations", H1)]
    lims = ["Heuristic and offline: no DNS, WHOIS, domain-age or URL-reputation lookups; a determined attacker "
            "using a clean, aged domain can score lower than the true risk.",
            "Authentication-Results / Received-SPF are trusted as written. They are only reliable when added by "
            "your own receiving MTA; headers injected earlier in the chain can be forged.",
            "Return-Path mismatches and non-aligned DKIM also occur on legitimate bulk mail; those checks are "
            "deliberately low-weighted to limit false positives.",
            "The sample messages in this report are synthetic (fake domains, documentation IP ranges) and "
            "were created for demonstration. Weights should be tuned against real mail before production use."]
    story += [Paragraph(f"- {esc(x)}", BODY) for x in lims]
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan e-mails for phishing indicators and spoofing signs.")
    ap.add_argument("files", nargs="*", help=".eml files to analyse, or '-' for stdin")
    ap.add_argument("--demo", action="store_true", help="write sample e-mails to ./sample_emails and analyse them")
    ap.add_argument("--pdf", metavar="FILE", help="write the PDF audit report here")
    ap.add_argument("--json", metavar="FILE", help="write machine-readable results here")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress console output")
    args = ap.parse_args(argv)

    files = list(args.files)
    if args.demo:
        out = Path("sample_emails")
        out.mkdir(exist_ok=True)
        for name, text in sample_emails().items():
            (out / name).write_text(text, encoding="utf-8")
            files.append(str(out / name))
        args.pdf = args.pdf or "Phishing_Analysis_Report.pdf"
    if not files:
        ap.error("give at least one .eml file (or use --demo)")

    results = [analyze_file(f) for f in files]
    if not args.quiet:
        for r in results:
            print_result(r)
    if args.json:
        Path(args.json).write_text(json.dumps([asdict(r) for r in results], indent=2, default=str))
        print(f"JSON written to {args.json}")
    if args.pdf:
        build_pdf(results, args.pdf)
        print(f"PDF report written to {args.pdf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
