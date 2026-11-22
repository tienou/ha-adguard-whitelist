"""Pure functions for parsing and manipulating AdGuard Home whitelist rules."""
from __future__ import annotations

import re

from .const import CDN_PATTERNS, EDUCATIONAL_SITES

WHITELIST_RULE_RE = re.compile(
    r"^@@\|\|(?P<domain>[a-zA-Z0-9.\-]+)\^\$client='?(?P<client>[^']+)'?$"
)
DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def normalize_domain(value: str) -> str:
    """Convert an internationalized hostname and reject non-domain input."""
    domain = value.strip().removesuffix(".").encode("idna").decode("ascii").lower()
    if len(domain) > 253 or not all(
        DNS_LABEL_RE.fullmatch(label) for label in domain.split(".")
    ):
        raise ValueError("Invalid domain name")
    return domain


def _matches_rule(rule: str, domain: str, client_ip: str) -> bool:
    match = WHITELIST_RULE_RE.fullmatch(rule.strip())
    return bool(
        match
        and match.group("client") == client_ip
        and match.group("domain").lower() == domain
    )


def parse_whitelist_rules(all_rules: list[str], client_ip: str) -> list[str]:
    """Extract domains whitelisted for the given client IP."""
    domains: set[str] = set()
    for rule in all_rules:
        match = WHITELIST_RULE_RE.match(rule.strip())
        if match and match.group("client") == client_ip:
            domains.add(match.group("domain").lower())
    return sorted(domains)


def format_whitelist_rule(domain: str, client_ip: str) -> str:
    """Create a whitelist rule: @@||domain^$client='IP'."""
    return f"@@||{domain}^$client='{client_ip}'"


def add_domain_to_rules(
    all_rules: list[str], domain: str, client_ip: str
) -> list[str]:
    """Return a new rule list with the domain added (idempotent)."""
    new_rule = format_whitelist_rule(domain, client_ip)
    for rule in all_rules:
        if _matches_rule(rule, domain, client_ip):
            return list(all_rules)
    return list(all_rules) + [new_rule]


def remove_domain_from_rules(
    all_rules: list[str], domain: str, client_ip: str
) -> list[str]:
    """Return a new rule list with the domain removed."""
    return [r for r in all_rules if not _matches_rule(r, domain, client_ip)]


def categorize_domain(domain: str) -> str:
    """Classify a domain as éducation, CDN, or autre."""
    for edu_domain in EDUCATIONAL_SITES:
        if domain == edu_domain or domain.endswith("." + edu_domain):
            return EDUCATIONAL_SITES[edu_domain]
    for pattern in CDN_PATTERNS:
        if pattern in domain:
            return "CDN / Technique"
    return "Autre"


def categorize_all(domains: list[str]) -> dict[str, list[str]]:
    """Group domains by category."""
    result: dict[str, list[str]] = {}
    for d in domains:
        cat = categorize_domain(d)
        result.setdefault(cat, []).append(d)
    return result
