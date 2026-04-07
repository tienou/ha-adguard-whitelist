"""dnsmasq whitelist management via SSH."""
from __future__ import annotations

import logging
import re

import asyncssh

from .const import DEFAULT_DNSMASQ_CONF_PATH, DEFAULT_UPSTREAM_DNS

_LOGGER = logging.getLogger(__name__)

# Matches: server=/domain.tld/9.9.9.9
DNSMASQ_SERVER_RE = re.compile(r"^server=/(?P<domain>[a-zA-Z0-9.\-]+)/(?P<dns>\S+)$")


def parse_dnsmasq_domains(content: str) -> list[str]:
    """Extract whitelisted domains from dnsmasq config content."""
    domains: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        match = DNSMASQ_SERVER_RE.match(line)
        if match:
            domains.append(match.group("domain"))
    return sorted(domains)


def add_domain_to_conf(content: str, domain: str, upstream_dns: str) -> str:
    """Add a server= line for a domain (idempotent)."""
    new_line = f"server=/{domain}/{upstream_dns}"
    for line in content.splitlines():
        if line.strip() == new_line:
            return content
    return content.rstrip("\n") + "\n" + new_line + "\n"


def remove_domain_from_conf(content: str, domain: str) -> str:
    """Remove all server= lines for a domain."""
    lines = content.splitlines(keepends=True)
    result = []
    for line in lines:
        match = DNSMASQ_SERVER_RE.match(line.strip())
        if match and match.group("domain") == domain:
            continue
        result.append(line)
    return "".join(result)


class DnsmasqSSH:
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
        self._host = host
        self._host_vpn = host_vpn
        self._port = port
        self._username = username
        self._password = password
        self._conf_path = conf_path
        self._upstream_dns = upstream_dns

    def _sudo(self, command: str) -> str:
        safe_pw = self._password.replace("'", "'\\''")
        return f"echo '{safe_pw}' | sudo -S {command}"

    async def _connect_and_run(self, host: str, command: str) -> str:
        """Connect to a specific host and run a command."""
        async with asyncssh.connect(
            host,
            port=self._port,
            username=self._username,
            password=self._password,
            known_hosts=None,
            client_keys=[],
        ) as conn:
            proc = await conn.create_process(command)
            stdout_data = await proc.stdout.read()
            await proc.wait_closed()
            return stdout_data or ""

    async def _execute(self, command: str) -> str:
        """Execute a command via SSH, with VPN fallback."""
        _LOGGER.debug("SSH connecting to %s@%s:%s", self._username, self._host, self._port)
        try:
            return await self._connect_and_run(self._host, command)
        except (OSError, asyncssh.DisconnectError) as err:
            if not self._host_vpn:
                raise
            _LOGGER.debug(
                "SSH to %s failed, trying VPN fallback %s: %s",
                self._host, self._host_vpn, err,
            )
            try:
                return await self._connect_and_run(self._host_vpn, command)
            except Exception as vpn_err:
                _LOGGER.error(
                    "SSH failed on both %s and VPN %s: %s / %s",
                    self._host, self._host_vpn, err, vpn_err,
                )
                raise

    async def test_connection(self) -> tuple[bool, str]:
        """Test SSH connection and read dnsmasq conf."""
        try:
            result = await self._execute("echo ok")
            if "ok" not in result:
                return False, "cannot_connect"
            # Also verify conf file is readable
            content = await self._execute(self._sudo(f"cat {self._conf_path}"))
            if not content.strip():
                return False, "conf_not_found"
            return True, ""
        except Exception as err:
            _LOGGER.error("dnsmasq SSH test failed: %s", err)
            return False, "cannot_connect"

    async def get_domains(self) -> list[str]:
        """Read dnsmasq conf and return whitelisted domains."""
        content = await self._execute(self._sudo(f"cat {self._conf_path}"))
        return parse_dnsmasq_domains(content)

    async def add_domain(self, domain: str) -> None:
        """Add a domain to the dnsmasq whitelist and restart."""
        content = await self._execute(self._sudo(f"cat {self._conf_path}"))
        new_content = add_domain_to_conf(content, domain, self._upstream_dns)
        if new_content == content:
            return  # Already present
        await self._write_conf(new_content)
        await self._restart_dnsmasq()
        _LOGGER.info("dnsmasq: added %s", domain)

    async def remove_domain(self, domain: str) -> None:
        """Remove a domain from the dnsmasq whitelist and restart."""
        content = await self._execute(self._sudo(f"cat {self._conf_path}"))
        new_content = remove_domain_from_conf(content, domain)
        if new_content == content:
            return  # Not present
        await self._write_conf(new_content)
        await self._restart_dnsmasq()
        _LOGGER.info("dnsmasq: removed %s", domain)

    async def _write_conf(self, content: str) -> None:
        """Write dnsmasq conf back via SSH."""
        cmd = (
            self._sudo(f"tee {self._conf_path}")
            + f" <<'ENDDNSMASQ'\n{content}ENDDNSMASQ"
        )
        await self._execute(cmd)

    async def _restart_dnsmasq(self) -> None:
        """Restart dnsmasq service."""
        await self._execute(self._sudo("systemctl restart dnsmasq"))
