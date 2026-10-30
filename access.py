"""Access-control comparison for authenticated scans.

The same pages are requested as different users (and as a visitor) and the answers are compared. Everything here is
GET-only, same-origin and bounded, and uses the pages the crawls already found; nothing is guessed or brute-forced.
Evidence never contains page text (it could be someone's personal data): only statuses, sizes and a similarity score.

What it can show:
  * a page that belongs to the logged-in area is also reachable without logging in;
  * a page that only user A was shown is readable by user B (broken access control / IDOR);
  * with a more privileged second account: a page only that account was shown is readable by the ordinary user.
What it cannot know: whether a shared page was *meant* to be shared. Where the owner's identity appears in the other
user's copy the result is strong; otherwise it is reported as "verify" with lower confidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from urllib.parse import urlparse

import auth

SENSITIVE_PATH = re.compile(r"admin|account|user|profile|order|invoice|billing|payment|setting|private|report|dashboard|member|customer|file|note|message|export|download", re.I)
MAX_URLS = 30
SIMILAR = 0.9


@dataclass
class Account:
    label: str                    # "account 1" / "account 2"
    session: object               # auth.AuthSession (logged in)
    urls: list = field(default_factory=list)        # pages this account was shown (crawl + API endpoints)
    identity: str = ""            # text that identifies this user's own data (username, e-mail)


@dataclass
class Page:
    status: int
    body: str
    final: str


def _path(url: str) -> str:
    return (urlparse(url).path or "/").rstrip("/") or "/"


def normalise(body: str, names) -> str:
    """Remove what legitimately differs between two users' copies of the same page, so only real differences remain."""
    text = body[:8000]
    for name in sorted({n for n in names if n}, key=len, reverse=True):
        text = re.sub(re.escape(name), "<user>", text, flags=re.I)
    text = re.sub(r"\b[0-9a-fA-F]{16,}\b", "<token>", text)       # CSRF tokens, session-like strings
    text = re.sub(r"\d{6,}", "<number>", text)                      # timestamps and long ids
    return re.sub(r"\s+", " ", text).strip()


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    matcher = SequenceMatcher(None, a, b, autojunk=False)
    if matcher.real_quick_ratio() < SIMILAR or matcher.quick_ratio() < SIMILAR:
        return 0.0
    return matcher.ratio()


def readable(fetcher_session, asked: str, page: Page) -> bool:
    """Did this fetch show content (as opposed to a refusal, a redirect away, or a login page)?"""
    if page.status != 200:
        return False
    if _path(page.final) != _path(asked):
        return False                                                 # redirected somewhere else, usually the login or an error page
    return not fetcher_session.looks_logged_out(page.status, page.body, page.final, asked)


def run(origin: str, first: Account, second: Account | None, relation: str, public_urls, visitor_fetch, checker) -> tuple[list, dict]:
    """Compare access. `visitor_fetch(url) -> Page` has no credentials. `checker` is a logged-in session used only to recognise login pages.

    relation: "peer" (two ordinary users) or "more_privileged" (the second account has more rights than the first).
    Returns (findings, status) in the same shapes the other stages use.
    """
    findings, rows = [], []
    public = {_path(u) for u in public_urls}
    budget = {"requests": 0}
    names = [first.identity, second.identity if second else ""]

    def get(who, url) -> Page | None:
        if budget["requests"] >= MAX_URLS * 4:
            return None
        budget["requests"] += 1
        try:
            if who is None:
                return visitor_fetch(url)
            status, _, body, final = who.session.request(url)
            return Page(status, body, final)
        except (auth.AuthError, OSError):
            return None

    def candidates(account: Account, exclude: set) -> list:
        seen, out = set(), []
        for url in account.urls:
            path = _path(url)
            if path in public or path in exclude or path in seen or auth.is_unsafe_url(url) or not auth.same_origin(url, origin):
                continue
            seen.add(path)
            out.append(url)
        return out[:MAX_URLS]

    def has_identity(account: Account, page: Page) -> bool:
        return bool(account.identity) and account.identity.lower() in page.body.lower()

    accounts = [first] + ([second] if second else [])
    tested = 0
    open_to_visitors = set()
    # 1. Pages from the logged-in area that a visitor can also open.
    for account in accounts:
        for url in candidates(account, set()):
            own = get(account, url)
            if own is None or not readable(account.session, url, own):
                continue
            tested += 1
            seen_by_visitor = get(None, url)
            if seen_by_visitor is None or not readable(checker, url, seen_by_visitor):
                rows.append({"url": url, "as": "visitor", "result": "refused"})
                continue
            score = similarity(normalise(own.body, names), normalise(seen_by_visitor.body, names))
            rows.append({"url": url, "as": "visitor", "result": "readable", "similarity": round(score, 2)})
            open_to_visitors.add(_path(url))
            if score < SIMILAR:
                continue
            personal = has_identity(account, seen_by_visitor)
            sensitive = bool(SENSITIVE_PATH.search(urlparse(url).path))
            severity = "High" if personal else "Medium" if sensitive else "Low"
            findings.append((severity, "Page from the logged-in area is reachable without logging in", url,
                             f"Found while logged in as {account.label}; requested again with no credentials it returned the same content "
                             f"(HTTP 200, {round(score * 100)}% identical)" + ("; it contains that user's identifying text." if personal else "."),
                             "Require authentication (and an ownership check) on the server for this URL, not only in the navigation.",
                             "High" if personal else "Medium" if sensitive else "Low"))

    # 2. Pages one user was shown that another user can also open.
    if second:
        pairs = [(second, first, candidates(second, {_path(u) for u in first.urls}), "more_privileged" if relation == "more_privileged" else "peer")]
        if relation != "more_privileged":
            pairs.append((first, second, candidates(first, {_path(u) for u in second.urls}), "peer"))
        for owner, other, urls, kind in pairs:
            for url in urls:
                if _path(url) in open_to_visitors:
                    continue                                 # open to everyone: already reported above, not a user-to-user problem
                mine = get(owner, url)
                if mine is None or not readable(owner.session, url, mine):
                    continue
                tested += 1
                theirs = get(other, url)
                if theirs is None or not readable(other.session, url, theirs):
                    rows.append({"url": url, "owner": owner.label, "as": other.label, "result": "refused"})
                    continue
                score = similarity(normalise(mine.body, names), normalise(theirs.body, names))
                rows.append({"url": url, "owner": owner.label, "as": other.label, "result": "readable", "similarity": round(score, 2)})
                if score < SIMILAR:
                    continue
                personal = has_identity(owner, theirs) and kind == "peer"
                if kind == "peer" and not personal and has_identity(other, theirs):
                    rows[-1]["result"] = "own copy"          # the same URL shows each user their own data (for example /api/me): not a leak
                    continue
                if kind == "more_privileged":
                    findings.append(("High", "Privileged page is reachable by an ordinary user (vertical access control)", url,
                                     f"This page was only shown to {owner.label} (the more privileged account). {other.label} opened it directly and received the same content "
                                     f"(HTTP 200, {round(score * 100)}% identical).",
                                     "Enforce the role check on the server for this URL and its API calls; hiding the link is not access control.", "Medium"))
                else:
                    findings.append(("High" if personal else "Medium", "Another user's page is readable (possible broken access control / IDOR)", url,
                                     f"This page was only shown to {owner.label}. {other.label} opened the URL directly and received the same content "
                                     f"(HTTP 200, {round(score * 100)}% identical)"
                                     + ("; the owner's identifying text appears in the other user's copy." if personal else ". Verify that this page is not meant to be shared."),
                                     "Check on the server that the logged-in user owns the object being requested (deny by default); do not rely on hidden or unguessable links.",
                                     "High" if personal else "Low"))

    unique = {}
    for item in findings:
        unique.setdefault((item[1], _path(item[2])), item)
    findings = list(unique.values())
    status = {"status": "completed", "finding_count": len(findings), "urls_compared": tested, "requests": budget["requests"],
              "second_account": bool(second), "relation": relation if second else "", "authenticated": True,
              "reason": (f"{tested} page(s) compared between " + ("a visitor, account 1 and account 2" if second else "a visitor and the logged-in user")
                         + f"; {len(findings)} issue(s)"), "rows": rows[:60]}
    return findings, status
