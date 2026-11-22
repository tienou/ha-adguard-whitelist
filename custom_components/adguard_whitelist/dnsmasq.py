"""dnsmasq whitelist management via SSH."""
from __future__ import annotations

import logging
import re
from ipaddress import ip_address
from shlex import quote

import asyncssh

from .const import DEFAULT_DNSMASQ_CONF_PATH, DEFAULT_UPSTREAM_DNS
from .ssh_client import SSHClient

_LOGGER = logging.getLogger(__name__)

# Matches: server=/domain.tld/9.9.9.9
DNSMASQ_SERVER_RE = re.compile(r"^server=/(?P<domain>[a-zA-Z0-9.\-]+)/(?P<dns>\S+)$")


def normalize_upstream(value: str) -> str:
    """Validate the address before putting it into a dnsmasq directive."""
    address = ip_address(value.strip())
    scope = getattr(address, "scope_id", None)
    if scope and not re.fullmatch(r"[a-zA-Z0-9_.-]+", scope):
        raise ValueError("Invalid IPv6 scope")
    return str(address)


def parse_dnsmasq_domains(content: str) -> list[str]:
    """Extract whitelisted domains from dnsmasq config content."""
    domains: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        match = DNSMASQ_SERVER_RE.match(line)
        if match:
            domains.add(match.group("domain").lower())
    return sorted(domains)


def add_domain_to_conf(content: str, domain: str, upstream_dns: str) -> str:
    """Add a server= line for a domain (idempotent)."""
    if domain in parse_dnsmasq_domains(content):
        return content
    prefix = content if not content or content.endswith("\n") else content + "\n"
    return f"{prefix}server=/{domain}/{upstream_dns}\n"


def remove_domain_from_conf(content: str, domain: str) -> str:
    """Remove all server= lines for a domain."""
    lines = content.splitlines(keepends=True)
    result = []
    for line in lines:
        match = DNSMASQ_SERVER_RE.match(line.strip())
        if match and match.group("domain").lower() == domain:
            continue
        result.append(line)
    return "".join(result)


_INSTALL_CONF = """
backup=$(mktemp) || exit 1
trap 'rm -f -- "$backup"' EXIT
cp -- "$2" "$backup" || exit 1
if cp -- "$1" "$2" && systemctl restart dnsmasq; then
    exit 0
fi
cp -- "$backup" "$2" && systemctl restart dnsmasq
exit 1
"""


class DnsmasqSSH(SSHClient):
    """Manage dnsmasq whitelist config via SSH."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        conf_path: str = DEFAULT_DNSMASQ_CONF_PATH,
        upstream_dns: str = DEFAULT_UPSTREAM_DNS,
        host_vpn: str | None = None,
    ) -> None:
        super().__init__(host, port, username, password, host_vpn)
        self._conf_path = conf_path
        self._upstream_dns = upstream_dns

    async def test_connection(self) -> tuple[bool, str]:
        """Test SSH connection and read dnsmasq conf."""
        try:
            normalize_upstream(self._upstream_dns)
        except ValueError:
            return False, "invalid_upstream_dns"

        try:
            await self.read_file(self._conf_path)
        except asyncssh.ProcessError:
            return False, "conf_not_found"
        except Exception as err:
            _LOGGER.error("dnsmasq SSH test failed: %s", err)
            return False, "cannot_connect"
        return True, ""

    async def get_domains(self) -> list[str]:
        """Read dnsmasq conf and return whitelisted domains."""
        content = await self.read_file(self._conf_path)
        return parse_dnsmasq_domains(content)

    async def add_domain(self, domain: str) -> None:
        """Add a domain to the dnsmasq whitelist and restart."""
        content = await self.read_file(self._conf_path)
        new_content = add_domain_to_conf(content, domain, normalize_upstream(self._upstream_dns))
        if new_content == content:
            return  # Already present
        await self.write_file(self._conf_path, new_content)
        _LOGGER.info("dnsmasq: added %s", domain)

    async def remove_domain(self, domain: str) -> None:
        """Remove a domain from the dnsmasq whitelist and restart."""
        content = await self.read_file(self._conf_path)
        new_content = remove_domain_from_conf(content, domain)
        if new_content == content:
            return  # Not present
        await self.write_file(self._conf_path, new_content)
        _LOGGER.info("dnsmasq: removed %s", domain)

    async def _install_file(
        self, conn: asyncssh.SSHClientConnection, staged: str, path: str,
    ) -> None:
        await self._sudo(conn, f"sh -c {quote(_INSTALL_CONF)} sh {staged} {path}")
