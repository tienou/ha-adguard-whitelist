"""Shared SSH transport for the remote configuration files."""
from __future__ import annotations

import logging
from shlex import quote

import asyncssh

_LOGGER = logging.getLogger(__name__)
_TIMEOUT = 10


class SSHClient:
    """Run checked commands on the LAN host, with a VPN fallback."""

    def __init__(
        self, host: str, port: int, username: str, password: str,
        host_vpn: str | None = None,
    ) -> None:
        self._host = host
        self._host_vpn = host_vpn
        self._port = port
        self._username = username
        self._password = password

    async def _connect(self) -> asyncssh.SSHClientConnection:
        for host in dict.fromkeys(filter(None, (self._host, self._host_vpn))):
            try:
                return await asyncssh.connect(
                    host,
                    port=self._port,
                    username=self._username,
                    password=self._password,
                    known_hosts=None,
                    client_keys=[],
                    connect_timeout=_TIMEOUT,
                )
            except (OSError, asyncssh.DisconnectError):
                if host == (self._host_vpn or self._host):
                    raise
                _LOGGER.debug("SSH unavailable on %s, trying %s", host, self._host_vpn)
        raise OSError("No SSH host configured")

    async def _sudo(self, conn: asyncssh.SSHClientConnection, command: str) -> str:
        result = await conn.run(
            f"sudo -S -p '' -- {command}",
            input=self._password + "\n",
            check=True,
            timeout=_TIMEOUT,
        )
        return result.stdout or ""

    async def read_file(self, path: str) -> str:
        async with await self._connect() as conn:
            return await self._sudo(conn, f"cat -- {quote(path)}")

    async def write_file(self, path: str, content: str) -> None:
        async with await self._connect() as conn:
            temp = await conn.run("mktemp", check=True, timeout=_TIMEOUT)
            staged = quote(temp.stdout.strip())
            try:
                await conn.run(
                    f"cat > {staged}", input=content, check=True, timeout=_TIMEOUT,
                )
                await self._install_file(conn, staged, quote(path))
            finally:
                try:
                    await conn.run(f"rm -f -- {staged}", check=True, timeout=_TIMEOUT)
                except (OSError, asyncssh.Error):
                    _LOGGER.debug("Could not remove the SSH staging file")

    async def _install_file(
        self, conn: asyncssh.SSHClientConnection, staged: str, path: str,
    ) -> None:
        await self._sudo(conn, f"cp -- {staged} {path}")
