"""Platform catalogue: recognise which CMS, e-commerce, admin console, business app or framework a site runs.

Pure functions only (no network, no subprocesses). Detection reads what the scanner already has: response
headers, cookie names, page markup, crawled URLs and WhatWeb fingerprint titles. Each platform lists:

  * how it is recognised (signatures),
  * the Nuclei template tags used for platform-targeted checks,
  * an optional dedicated tool (for example wpscan or droopescan) that goes deeper than Nuclei.

Detection is deliberately conservative: a platform is reported only when a specific signature matches, and
weak, generic hints (such as a bare PHPSESSID cookie) are never enough on their own.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Platform:
    id: str
    name: str
    group: str                       # cms, ecommerce, community, devops, business, framework, frontend
    nuclei_tags: tuple = ()          # tags used to pick platform-targeted Nuclei templates
    headers: tuple = ()              # (header-name, regex) pairs; the header value must match
    cookies: tuple = ()              # regexes matched against cookie names
    body: tuple = ()                 # regexes matched against the page markup
    urls: tuple = ()                 # regexes matched against crawled URLs
    dedicated_tool: str = ""         # registry id of a dedicated engine, if one exists
    hosted: bool = False             # a hosted service: only the storefront/site can be assessed, not the platform
    note: str = ""


def _p(id, name, group, tags, **kw):
    return Platform(id=id, name=name, group=group, nuclei_tags=tuple(tags), **kw)


PLATFORMS = (
    # ---- content management ----
    _p("wordpress", "WordPress", "cms", ("wordpress",), dedicated_tool="wpscan",
       body=(r"wp-content/|wp-includes/|/wp-json/", r"<meta[^>]+name=[\"']generator[\"'][^>]+WordPress"),
       headers=(("link", r"rel=[\"']https://api\.w\.org/"),), cookies=(r"^wordpress_", r"^wp-settings-")),
    _p("joomla", "Joomla", "cms", ("joomla",), dedicated_tool="droopescan",
       body=(r"/components/com_[a-z0-9_]+/", r"<meta[^>]+name=[\"']generator[\"'][^>]+Joomla", r"/media/jui/", r"/media/system/js/")),
    _p("drupal", "Drupal", "cms", ("drupal",), dedicated_tool="droopescan",
       headers=(("x-generator", r"Drupal"), ("x-drupal-cache", r".")),
       body=(r"Drupal\.settings", r"/sites/default/files/", r"data-drupal-", r"<meta[^>]+name=[\"']generator[\"'][^>]+Drupal")),
    _p("typo3", "TYPO3", "cms", ("typo3",), body=(r"typo3conf/|typo3temp/", r"<meta[^>]+name=[\"']generator[\"'][^>]+TYPO3")),
    _p("silverstripe", "SilverStripe", "cms", ("silverstripe",), dedicated_tool="droopescan",
       body=(r"<meta[^>]+name=[\"']generator[\"'][^>]+SilverStripe",)),
    _p("ghost", "Ghost", "cms", ("ghost",), headers=(("x-ghost-cache-status", r"."),),
       body=(r"<meta[^>]+name=[\"']generator[\"'][^>]+Ghost",)),
    _p("umbraco", "Umbraco", "cms", ("umbraco",), body=(r"/umbraco/|/App_Plugins/",), cookies=(r"^UMB[-_]",)),
    _p("craftcms", "Craft CMS", "cms", ("craftcms",), headers=(("x-powered-by", r"Craft CMS"),), cookies=(r"^CraftSessionId$",)),
    _p("modx", "MODX", "cms", ("modx",), body=(r"<meta[^>]+name=[\"']generator[\"'][^>]+MODX", r"/assets/components/")),
    _p("concrete", "Concrete CMS", "cms", ("concrete5", "concretecms"), cookies=(r"^CONCRETE5$",),
       body=(r"<meta[^>]+name=[\"']generator[\"'][^>]+(concrete5|Concrete CMS)", r"/concrete/js/")),
    _p("aem", "Adobe Experience Manager", "cms", ("aem",), body=(r"/etc\.clientlibs/", r"/etc/designs/", r"/content/dam/")),
    _p("liferay", "Liferay", "cms", ("liferay",), headers=(("liferay-portal", r"."),), body=(r"Liferay\.ThemeDisplay", r"/o/frontend-js-web/")),
    _p("sitecore", "Sitecore", "cms", ("sitecore",), cookies=(r"^SC_ANALYTICS_GLOBAL_COOKIE$",), body=(r"/sitecore/",)),
    # ---- e-commerce ----
    _p("magento", "Magento / Adobe Commerce", "ecommerce", ("magento",),
       body=(r"/static/frontend/Magento_", r"text/x-magento-init", r"Mage\.Cookies", r"/skin/frontend/"), cookies=(r"^mage-cache-sessid$", r"^form_key$")),
    _p("prestashop", "PrestaShop", "ecommerce", ("prestashop",), body=(r"<meta[^>]+name=[\"']generator[\"'][^>]+PrestaShop", r"var prestashop\s*=", r"/modules/ps_")),
    _p("opencart", "OpenCart", "ecommerce", ("opencart",), body=(r"catalog/view/(theme|javascript)/",), cookies=(r"^OCSESSID$",)),
    _p("woocommerce", "WooCommerce", "ecommerce", ("woocommerce",), dedicated_tool="wpscan",
       body=(r"/wp-content/plugins/woocommerce/", r"wc-ajax=", r"woocommerce-"),
       note="A WordPress plugin; covered by the WordPress checks."),
    _p("shopify", "Shopify (hosted)", "ecommerce", ("shopify",), hosted=True,
       headers=(("x-shopid", r"."), ("x-shopify-stage", r".")), body=(r"cdn\.shopify\.com",),
       note="A hosted service: only the storefront can be assessed, not the Shopify platform itself."),
    # ---- learning and community ----
    _p("moodle", "Moodle", "community", ("moodle",), dedicated_tool="droopescan", cookies=(r"^MoodleSession",),
       body=(r"M\.cfg\s*=", r"/theme/yui_combo\.php", r"<meta[^>]+name=[\"']keywords[\"'][^>]+moodle")),
    _p("mediawiki", "MediaWiki", "community", ("mediawiki",), body=(r"<meta[^>]+name=[\"']generator[\"'][^>]+MediaWiki", r"/load\.php\?")),
    _p("phpbb", "phpBB", "community", ("phpbb",), cookies=(r"^phpbb3_",), body=(r"Powered by .{0,40}phpBB",)),
    _p("discourse", "Discourse", "community", ("discourse",), headers=(("x-discourse-route", r"."),),
       body=(r"<meta[^>]+name=[\"']generator[\"'][^>]+Discourse",)),
    _p("vbulletin", "vBulletin", "community", ("vbulletin",), cookies=(r"^bb(session|lastvisit|lastactivity)hash$", r"^bb_"), body=(r"vBulletin",)),
    # ---- admin and DevOps consoles ----
    _p("jenkins", "Jenkins", "devops", ("jenkins",), headers=(("x-jenkins", r"."), ("x-hudson", r".")), body=(r"<title>[^<]*Jenkins", r"jenkins-version")),
    _p("gitlab", "GitLab", "devops", ("gitlab",), cookies=(r"^_gitlab_session$",), body=(r"<meta[^>]+content=[\"']GitLab[\"']", r"gon\.gitlab_url")),
    _p("gitea", "Gitea", "devops", ("gitea",), cookies=(r"^i_like_gitea$",), body=(r"Powered by Gitea", r"<meta[^>]+name=[\"']keywords[\"'][^>]+gitea")),
    _p("grafana", "Grafana", "devops", ("grafana",), cookies=(r"^grafana_session$",), body=(r"<title>Grafana</title>", r"grafanaBootData")),
    _p("kibana", "Kibana", "devops", ("kibana",), headers=(("kbn-name", r"."), ("kbn-license-sig", r".")), body=(r"<title>Elastic</title>",)),
    _p("sonarqube", "SonarQube", "devops", ("sonarqube",), body=(r"<title>SonarQube</title>", r"/sonar/|SonarQube")),
    _p("nexus", "Sonatype Nexus", "devops", ("nexus",), body=(r"Nexus Repository Manager", r"Sonatype Nexus")),
    _p("artifactory", "JFrog Artifactory", "devops", ("artifactory", "jfrog"), body=(r"JFrog Artifactory", r"<title>Artifactory")),
    _p("portainer", "Portainer", "devops", ("portainer",), body=(r"<title>Portainer", r"portainer\.io")),
    _p("phpmyadmin", "phpMyAdmin", "devops", ("phpmyadmin",), cookies=(r"^phpMyAdmin$", r"^pma[A-Z_a-z]"), body=(r"<title>phpMyAdmin", r"pma_theme")),
    _p("adminer", "Adminer", "devops", ("adminer",), body=(r"<title>Login - Adminer", r"adminer\.org")),
    _p("tomcat", "Apache Tomcat", "devops", ("tomcat",), headers=(("server", r"Apache-Coyote"),),
       body=(r"<title>Apache Tomcat", r"Apache Tomcat/[0-9]")),
    _p("webmin", "Webmin", "devops", ("webmin",), headers=(("server", r"MiniServ"),), body=(r"<title>Login to Webmin", r"Webmin")),
    _p("cpanel", "cPanel / WHM", "devops", ("cpanel",), body=(r"cPanel", r"cpsess"), cookies=(r"^cpsession$", r"^whostmgrsession$")),
    _p("plesk", "Plesk", "devops", ("plesk",), headers=(("x-powered-by", r"Plesk"),), body=(r"<title>Plesk", r"Plesk Obsidian")),
    # ---- business applications ----
    _p("confluence", "Atlassian Confluence", "business", ("confluence",), headers=(("x-confluence-request-time", r"."),),
       body=(r"ajs-confluence", r"Atlassian Confluence"), cookies=(r"^confluence-",)),
    _p("jira", "Atlassian Jira", "business", ("jira",), headers=(("x-ausername", r"."), ("x-arequestid", r".")),
       body=(r"ajs-version-number", r"Atlassian JIRA"), cookies=(r"^atlassian\.xsrf\.token$",)),
    _p("nextcloud", "Nextcloud", "business", ("nextcloud",), headers=(("x-nextcloud-", r"."),), body=(r"<title>[^<]*Nextcloud", r"nextcloud-")),
    _p("owncloud", "ownCloud", "business", ("owncloud",), body=(r"<title>[^<]*ownCloud", r"owncloud-")),
    _p("roundcube", "Roundcube", "business", ("roundcube",), cookies=(r"^roundcube_sessid$",), body=(r"rcmail", r"Roundcube Webmail")),
    _p("zimbra", "Zimbra", "business", ("zimbra",), cookies=(r"^ZM_",), body=(r"Zimbra Web Client", r"/zimbra/")),
    _p("sharepoint", "Microsoft SharePoint", "business", ("sharepoint",), headers=(("microsoftsharepointteamservices", r"."), ("sprequestguid", r"."))),
    _p("owa", "Outlook Web App / Exchange", "business", ("exchange", "owa"), headers=(("x-owa-version", r"."),), body=(r"Outlook Web App", r"/owa/auth/")),
    # ---- application frameworks and servers ----
    _p("laravel", "Laravel", "framework", ("laravel",), cookies=(r"^laravel_session$",), body=(r"laravel_session",)),
    _p("symfony", "Symfony", "framework", ("symfony",), headers=(("x-debug-token", r"."), ("x-debug-token-link", r".")), cookies=(r"^sf_redirect$",)),
    _p("django", "Django", "framework", ("django",), cookies=(r"^csrftoken$",), body=(r"csrfmiddlewaretoken",)),
    _p("flask", "Flask / Werkzeug", "framework", ("flask", "werkzeug"), headers=(("server", r"Werkzeug"),)),
    _p("rails", "Ruby on Rails", "framework", ("rails",), headers=(("x-runtime", r"^[0-9.]+$"),),
       body=(r"<meta[^>]+name=[\"']csrf-param[\"']", r"authenticity_token")),
    _p("springboot", "Spring / Spring Boot", "framework", ("springboot", "spring"), headers=(("x-application-context", r"."),),
       body=(r"Whitelabel Error Page",)),
    _p("express", "Express (Node.js)", "framework", ("expressjs",), headers=(("x-powered-by", r"^Express"),)),
    _p("aspnet", "ASP.NET", "framework", ("aspnet", "asp.net"),
       headers=(("x-aspnet-version", r"."), ("x-aspnetmvc-version", r"."), ("x-powered-by", r"ASP\.NET")),
       cookies=(r"^ASP\.NET_SessionId$", r"^\.ASPXAUTH$"), body=(r"name=[\"']__VIEWSTATE[\"']",)),
    _p("nextjs", "Next.js", "framework", ("nextjs",), headers=(("x-powered-by", r"Next\.js"),), body=(r"__NEXT_DATA__", r"/_next/static/")),
    _p("nuxt", "Nuxt", "framework", ("nuxt", "nuxtjs"), body=(r"window\.__NUXT__", r"/_nuxt/")),
    _p("struts", "Apache Struts", "framework", ("struts",), urls=(r"\.action(\?|$)", r"/struts/")),
    _p("coldfusion", "Adobe ColdFusion", "framework", ("coldfusion",), headers=(("x-powered-by", r"ColdFusion"),),
       cookies=(r"^CFID$", r"^CFTOKEN$"), urls=(r"\.cfm(\?|$)",)),
    # ---- front-end frameworks (these shape how much of the site a crawler can see) ----
    _p("angular", "Angular", "frontend", (), body=(r"<app-root", r"\bng-version=[\"']", r"ng-app=")),
    _p("react", "React", "frontend", (), body=(r"data-reactroot", r"<div id=[\"']root[\"']></div>", r"/static/js/(main|bundle)[.\w-]*\.js")),
    _p("vue", "Vue.js", "frontend", (), body=(r"<div id=[\"']app[\"']></div>", r"data-v-[0-9a-f]{6,}")),
)

BY_ID = {platform.id: platform for platform in PLATFORMS}
GROUP_LABELS = {"cms": "Content management", "ecommerce": "E-commerce", "community": "Learning and community",
                "devops": "Admin and DevOps consoles", "business": "Business applications",
                "framework": "Application frameworks", "frontend": "Front-end frameworks"}
SPA_PLATFORMS = {"angular", "react", "vue", "nextjs", "nuxt"}


def cookie_names_from_headers(set_cookie_values) -> list[str]:
    """Cookie names from one or more Set-Cookie header values."""
    names = []
    for value in set_cookie_values or []:
        match = re.match(r"\s*([^=;\s]+)=", str(value))
        if match and match.group(1) not in names:
            names.append(match.group(1))
    return names


def detect_platforms(headers: dict | None, body: str | None, cookie_names=(), urls=(), fingerprint_titles=()) -> dict:
    """Return {platform_id: {"confidence": "high"|"medium", "evidence": [...]}} for every recognised platform.

    Two independent kinds of evidence (for example a header and a markup match) give "high" confidence; a single
    specific signature gives "medium". A WhatWeb fingerprint of the platform's name counts as one more signal.
    """
    lowered_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    text = body or ""
    cookie_names = [str(name) for name in cookie_names or []]
    urls = [str(url) for url in urls or []]
    fingerprint_words = set(re.findall(r"[a-z0-9.+]+", " ".join(str(t) for t in fingerprint_titles or []).lower()))
    found = {}
    for platform in PLATFORMS:
        evidence = []
        for name, pattern in platform.headers:
            value = next((v for k, v in lowered_headers.items() if k == name or (name.endswith("-") and k.startswith(name))), None)
            if value is not None and re.search(pattern, value, re.I):
                evidence.append(f"header {name}")
        for pattern in platform.cookies:
            hit = next((c for c in cookie_names if re.search(pattern, c)), None)
            if hit:
                evidence.append(f"cookie {hit}")
        if text:
            for pattern in platform.body:
                if re.search(pattern, text[:600_000], re.I):
                    evidence.append("page markup")
                    break
        for pattern in platform.urls:
            if any(re.search(pattern, url) for url in urls):
                evidence.append("URL pattern")
                break
        # A WhatWeb fingerprint counts only when it names the platform itself (never just "Apache" for Tomcat or Struts).
        if {platform.id, platform.name.lower().replace(" ", "")} & fingerprint_words:
            evidence.append("fingerprint")
        if evidence:
            kinds = {item.split(" ")[0] for item in evidence}
            found[platform.id] = {"confidence": "high" if len(kinds) >= 2 else "medium", "evidence": sorted(set(evidence))}
    # WooCommerce is a WordPress plugin, so it always implies WordPress.
    if "woocommerce" in found and "wordpress" not in found:
        found["wordpress"] = {"confidence": "medium", "evidence": ["implied by WooCommerce"]}
    return found


def nuclei_tags_for(platform_ids) -> list[str]:
    """Union of Nuclei tags for the given platforms, in a stable order."""
    tags = []
    for platform_id in platform_ids:
        for tag in BY_ID[platform_id].nuclei_tags if platform_id in BY_ID else ():
            if tag not in tags:
                tags.append(tag)
    return tags


def describe(platform_ids) -> list[dict]:
    """Plain-language rows for reports: id, name, group, whether a dedicated tool exists."""
    rows = []
    for platform_id in platform_ids:
        platform = BY_ID.get(platform_id)
        if platform:
            rows.append({"id": platform.id, "name": platform.name, "group": GROUP_LABELS.get(platform.group, platform.group),
                         "dedicated_tool": platform.dedicated_tool, "hosted": platform.hosted, "note": platform.note})
    return rows
