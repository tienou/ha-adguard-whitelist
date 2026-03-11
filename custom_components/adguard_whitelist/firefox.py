"""Pure functions for reading/writing Firefox policies.json bookmarks."""
from __future__ import annotations

import json


def parse_policies(raw_json: str) -> dict:
    """Parse policies.json content."""
    return json.loads(raw_json)


def get_bookmarks(policies: dict) -> list[dict]:
    """Extract the Bookmarks list from policies."""
    return policies.get("policies", {}).get("Bookmarks", [])


def add_bookmark(policies: dict, domain: str, title: str | None = None) -> dict:
    """Return a new policies dict with a bookmark added (idempotent)."""
    url = f"https://{domain}"
    if title is None:
        title = domain.split(".")[0].capitalize()

    bookmarks = list(get_bookmarks(policies))

    # Check if already exists
    for bm in bookmarks:
        if bm.get("URL", "").rstrip("/") == url.rstrip("/"):
            return policies

    bookmarks.append({
        "Title": title,
        "URL": url,
        "Placement": "toolbar",
    })

    result = json.loads(json.dumps(policies))
    result.setdefault("policies", {})["Bookmarks"] = bookmarks
    return result


def remove_bookmark(policies: dict, domain: str) -> dict:
    """Return a new policies dict with the bookmark removed."""
    url = f"https://{domain}"

    bookmarks = get_bookmarks(policies)
    new_bookmarks = [
        bm for bm in bookmarks
        if bm.get("URL", "").rstrip("/") != url.rstrip("/")
    ]

    result = json.loads(json.dumps(policies))
    result.setdefault("policies", {})["Bookmarks"] = new_bookmarks
    return result


def get_bookmark_domains(policies: dict) -> set[str]:
    """Extract the set of bookmarked domains from policies."""
    domains: set[str] = set()
    for bm in get_bookmarks(policies):
        url = bm.get("URL", "")
        # Extract domain from https://domain or http://domain
        if "://" in url:
            domain = url.split("://", 1)[1].split("/")[0].lower()
            if domain.startswith("www."):
                domain = domain[4:]
            domains.add(domain)
    return domains


def serialize_policies(policies: dict) -> str:
    """Serialize policies dict to formatted JSON."""
    return json.dumps(policies, indent=2, ensure_ascii=False) + "\n"
