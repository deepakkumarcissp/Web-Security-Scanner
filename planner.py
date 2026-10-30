"""Assessment planner: decides which specialist checks apply to a target and reports honestly what was not covered.

Pure functions only (no network, no subprocesses) so the rules are easy to test and to extend.
Adding a new engine means: add a rule here, then add its stage in app.py (ENGINE_STAGES + a runner).
A rule whose engine is not built yet is never silently ignored: it is reported as a coverage note.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import platforms

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
    needs_flags: tuple = ()  # applies only when these facts are true (for example "login_form")
    unless_flags: tuple = () # does not apply when any of these facts is true (for example "authenticated")
    fixed_message: str = ""  # the exact coverage note to show when the rule applies but cannot be satisfied
    tool_label: str = ""     # plain-language name of the missing capability, used in coverage notes


RULES = (
    Rule("content_discovery", "Hidden content and path discovery", "ffuf", ("deep", "active"),
         "Deep and Active profiles include hidden content discovery",
         gap_note="Hidden files and directories that are not linked from any page were not searched for."),
    Rule("wordpress", "WordPress-specific checks", "wpscan", ("standard", "deep", "active"),
         "WordPress was detected", technologies=("wordpress",),
         gap_note="WordPress plugins, themes and user exposure were not checked."),
    Rule("joomla", "Joomla-specific checks", "droopescan", ("standard", "deep", "active"),
         "Joomla was detected", technologies=("joomla",),
         gap_note="Joomla version, components and exposed files were not checked beyond general template checks."),
    Rule("drupal", "Drupal-specific checks", "droopescan", ("standard", "deep", "active"),
         "Drupal was detected", technologies=("drupal",),
         gap_note="Drupal version, modules and exposed files were not checked beyond general template checks."),
    Rule("silverstripe", "SilverStripe-specific checks", "droopescan", ("standard", "deep", "active"),
         "SilverStripe was detected", technologies=("silverstripe",),
         gap_note="SilverStripe version and modules were not checked beyond general template checks."),
    Rule("moodle", "Moodle-specific checks", "droopescan", ("standard", "deep", "active"),
         "Moodle was detected", technologies=("moodle",),
         gap_note="Moodle version and plugins were not checked beyond general template checks."),
    Rule("forms_and_apis", "Form, API and script-endpoint analysis", "builtin-forms-api", ("standard", "deep", "active"),
         "Standard and deeper profiles analyse forms, scripts and API descriptions"),
    Rule("authenticated_scan", "Authenticated crawl and analysis", "builtin-authenticated", ("quick", "standard", "deep", "active"),
         "Credentials were provided and the login worked", needs_flags=("authenticated",)),
    Rule("access_control", "Access-control comparison between users", "builtin-access-control", ("standard", "deep", "active"),
         "Two accounts logged in", needs_flags=("second_account",)),
    Rule("access_control_one_account", "Access-control comparison between users", "second-account", ("standard", "deep", "active"),
         "Credentials were provided", needs_flags=("authenticated",), unless_flags=("second_account",), tool_label="a second account",
         fixed_message="Only one account was provided, so the scanner could only compare that user with a visitor. Whether one user can open another user's "
                       "pages was not tested. Add a second account under 'Authenticated scan' to test it."),
    Rule("access_control_limits", "Access-control testing beyond linked pages", "access-control-deep", ("standard", "deep", "active"),
         "Credentials were provided", needs_flags=("authenticated",), tool_label="object-level access testing",
         fixed_message="Access control was compared only for pages and API endpoints the crawl found. Actions that change data (they are never sent), "
                       "object IDs that no page links to, and role-specific buttons or fields were not tested."),
    Rule("login_testing", "Testing behind the login", "login-credentials", ("standard", "deep", "active"),
         "A login form was found", needs_flags=("login_form",), unless_flags=("authenticated", "auth_attempted"), tool_label="login credentials",
         fixed_message="A login form was found, but no credentials were provided, so everything behind the login was not tested. "
                       "Add credentials under 'Authenticated scan' to test it."),
    Rule("login_hardening", "Login hardening tests", "login-hardening", ("standard", "deep", "active"),
         "A login form was found", needs_flags=("login_form",), tool_label="login-hardening tests",
         fixed_message="A login form was found. Brute-force resistance, account lockout and multi-factor behaviour were not tested: "
                       "the scanner never guesses passwords."),
    Rule("upload_testing", "File-upload restriction testing", "upload-testing", ("standard", "deep", "active"),
         "A file-upload form was found", needs_flags=("upload_form",), tool_label="an upload-testing engine",
         gap_note="Allowed file types, size limits and content checks were not tested."),
    Rule("authenticated_api", "Authenticated API testing", "login-credentials", ("standard", "deep", "active"),
         "API endpoints that require authentication were found", needs_flags=("api_requires_auth",), unless_flags=("authenticated",),
         tool_label="login credentials",
         fixed_message="API endpoints answered 401 or 403 and were not tested behind a login. Add credentials under 'Authenticated scan' to test them."),
    Rule("graphql_testing", "Dedicated GraphQL testing", "graphql-testing", ("standard", "deep", "active"),
         "A GraphQL endpoint was found", needs_flags=("graphql",), tool_label="a GraphQL testing engine",
         gap_note="Only introspection was checked; query depth limits, batching and field-level authorization were not tested."),
    Rule("spa_crawling", "Single-page-app crawling", "chromium", ("standard", "deep", "active"),
         "This is a JavaScript single-page app", needs_flags=("is_spa",), tool_label="a browser-based crawler",
         gap_note="Screens that exist only in the browser are not crawled. Endpoints named in the scripts were extracted and checked, but behaviour that only exists at runtime may be missed."),
    Rule("spa_interaction", "Interaction with the single-page app", "browser-interaction", ("standard", "deep", "active"),
         "This is a JavaScript single-page app", needs_flags=("is_spa",), tool_label="browser interaction",
         fixed_message="The app was rendered in a browser and its links, forms and API calls were read, but nothing was clicked, typed or submitted. "
                       "Screens that appear only after clicking a button, scrolling or filling a form were not reached, and write requests the app made were blocked, never sent."),
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
    technologies: set = field(default_factory=set)   # detected platform ids (see platforms.py)
    has_parameters: bool = False
    url_count: int = 0
    https: bool = False
    login_form: bool = False        # a form with a password field was found
    upload_form: bool = False       # a file-upload form was found
    is_spa: bool = False            # a JavaScript single-page app: most pages are built in the browser
    graphql: bool = False           # a GraphQL endpoint answered
    api_requires_auth: bool = False  # API endpoints answered 401/403
    api_endpoints: int = 0
    authenticated: bool = False     # credentials were provided and the login worked
    auth_attempted: bool = False    # credentials were provided (whether or not the login worked)
    second_account: bool = False    # a second account logged in, so users can be compared


def detect_technologies(headers: dict | None, body: str | None, fingerprint_titles=(), cookie_names=(), urls=()) -> set:
    """Ids of recognised platforms (WordPress, Joomla, Jira, Laravel, ...). See platforms.py for the catalogue."""
    return set(platforms.detect_platforms(headers, body, cookie_names=cookie_names, urls=urls,
                                          fingerprint_titles=fingerprint_titles))


def has_query_parameters(urls) -> bool:
    return any(urlparse(str(url)).query for url in urls or [])


def rule_applies(rule: Rule, facts: Facts) -> bool:
    if facts.profile not in rule.profiles:
        return False
    if rule.technologies and not (set(rule.technologies) & facts.technologies):
        return False
    if rule.needs_parameters and not facts.has_parameters:
        return False
    if any(not getattr(facts, flag, False) for flag in rule.needs_flags):
        return False
    if any(getattr(facts, flag, False) for flag in rule.unless_flags):
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
            if rule.fixed_message:
                entry["message"] = rule.fixed_message
            elif rule.tool_label:
                entry["message"] = f"{rule.reason}. {rule.capability} needs {rule.tool_label}, which is not available in this version. {rule.gap_note}".strip()
            else:
                entry["message"] = (f"{rule.reason}. {rule.capability} ({rule.tool}) would normally run here, "
                                    f"but it is not available in this version. {rule.gap_note}").strip()
            not_covered.append(entry)
    covered = []
    for row in platforms.describe(sorted(facts.technologies)):
        platform = platforms.BY_ID[row["id"]]
        if platform.dedicated_tool and platform.dedicated_tool in available_tools:
            how = f"{platform.dedicated_tool} plus platform-targeted Nuclei templates"
        elif platform.dedicated_tool:
            how = "platform-targeted Nuclei templates only (the dedicated tool is not available in this version)"
        elif platform.nuclei_tags:
            how = "platform-targeted Nuclei templates"
        else:
            how = "front-end framework: affects how much of the site a crawler can see"
        covered.append({**row, "covered_by": how})
    return {"planned": planned, "not_covered": not_covered, "platforms": covered,
            "facts": {"technologies": sorted(facts.technologies), "has_parameters": facts.has_parameters,
                      "urls_mapped": facts.url_count, "login_form": facts.login_form, "upload_form": facts.upload_form,
                      "is_spa": facts.is_spa, "graphql": facts.graphql, "api_requires_auth": facts.api_requires_auth,
                      "api_endpoints": facts.api_endpoints, "authenticated": facts.authenticated, "auth_attempted": facts.auth_attempted}}
