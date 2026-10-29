"""Assessment planner: decides which specialist checks apply to a target and reports honestly what was not covered.

Pure functions only (no network, no subprocesses) so the rules are easy to test and to extend.
Adding a new engine means: add a rule here, then add its stage in app.py (ENGINE_STAGES + a runner).
A rule whose engine is not built yet is never silently ignored: it is reported as a coverage note.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

PROFILES = ("quick", "standard", "deep", "active")


@dataclass(frozen=True)
class Rule:
    id: str
    capability: str          # what the check is, in plain words
    tool: str                # registry id of the tool that performs it
    profiles: tuple          # profiles in which the check applies
    reason: str              # why it applies (shown to the assessor)
    technologies: tuple = ()  # applies only when one of these technologies was detected
    needs_parameters: bool = False  # applies only when URLs with query parameters were found
    gap_note: str = ""       # what to tell the assessor when the engine is not available


RULES = (
    Rule("content_discovery", "Hidden content and path discovery", "ffuf", ("deep", "active"),
         "Deep and Active profiles include hidden content discovery",
         gap_note="Hidden files and directories that are not linked from any page were not searched for."),
    Rule("wordpress", "WordPress-specific checks", "wpscan", ("standard", "deep", "active"),
         "WordPress was detected", technologies=("wordpress",),
         gap_note="WordPress plugins, themes and user exposure were not checked."),
    Rule("joomla", "Joomla-specific checks", "joomscan", ("standard", "deep", "active"),
         "Joomla was detected", technologies=("joomla",),
         gap_note="Joomla components and known core issues were not checked."),
    Rule("drupal", "Drupal-specific checks", "droopescan", ("standard", "deep", "active"),
         "Drupal was detected", technologies=("drupal",),
         gap_note="Drupal modules and known core issues were not checked."),
    Rule("sql_injection", "Deep SQL injection testing", "sqlmap", ("active",),
         "URLs with query parameters were found and the Active profile was approved", needs_parameters=True,
         gap_note="Wapiti's general injection tests ran, but dedicated SQL injection testing did not."),
    Rule("xss", "Dedicated cross-site scripting testing", "dalfox", ("active",),
         "URLs with query parameters were found and the Active profile was approved", needs_parameters=True,
         gap_note="Wapiti's general tests ran, but dedicated XSS testing did not."),
)


@dataclass
class Facts:
    profile: str
    technologies: set = field(default_factory=set)
    has_parameters: bool = False
    url_count: int = 0
    https: bool = False


_TECH_SIGNATURES = {
    "wordpress": re.compile(r"wp-content|wp-includes|wp-json|content=[\"']wordpress", re.I),
    "joomla": re.compile(r"/components/com_|content=[\"']joomla|joomla!", re.I),
    "drupal": re.compile(r"drupal\.settings|sites/default/files|content=[\"']drupal", re.I),
}
_KNOWN_NAMES = ("wordpress", "joomla", "drupal")


def detect_technologies(headers: dict | None, body: str | None, fingerprint_titles=()) -> set:
    """Names of recognised technologies, from response headers, page markup and fingerprint results."""
    found = set()
    haystack_parts = [body or ""]
    for key, value in (headers or {}).items():
        haystack_parts.append(f"{key}: {value}")
    haystack = "\n".join(haystack_parts)
    for name, pattern in _TECH_SIGNATURES.items():
        if pattern.search(haystack):
            found.add(name)
    # Servers and CMSs often name themselves in headers (X-Generator: Drupal 10, X-Powered-By: ...).
    header_text = " ".join(f"{k} {v}" for k, v in (headers or {}).items()).lower()
    for name in _KNOWN_NAMES:
        if name in header_text:
            found.add(name)
    for title in fingerprint_titles:
        lowered = str(title).lower()
        for name in _KNOWN_NAMES:
            if name in lowered:
                found.add(name)
    return found


def has_query_parameters(urls) -> bool:
    return any(urlparse(str(url)).query for url in urls or [])


def rule_applies(rule: Rule, facts: Facts) -> bool:
    if facts.profile not in rule.profiles:
        return False
    if rule.technologies and not (set(rule.technologies) & facts.technologies):
        return False
    if rule.needs_parameters and not facts.has_parameters:
        return False
    return True


def plan_coverage(facts: Facts, available_tools: set) -> dict:
    """Split the applicable rules into checks that can run and coverage notes for those that cannot."""
    planned, not_covered = [], []
    for rule in RULES:
        if not rule_applies(rule, facts):
            continue
        entry = {"rule": rule.id, "capability": rule.capability, "tool": rule.tool, "reason": rule.reason}
        if rule.tool in available_tools:
            planned.append(entry)
        else:
            entry["message"] = (f"{rule.reason}. {rule.capability} ({rule.tool}) would normally run here, "
                                f"but it is not available in this version. {rule.gap_note}").strip()
            not_covered.append(entry)
    return {"planned": planned, "not_covered": not_covered,
            "facts": {"technologies": sorted(facts.technologies), "has_parameters": facts.has_parameters,
                      "urls_mapped": facts.url_count}}
