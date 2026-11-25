"""Shared SSH transport for the remote configuration files."""
from __future__ import annotations

import asyncio
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

    async def _run(
        self, conn: asyncssh.SSHClientConnection, command: str, input: str | None = None,
    ) -> str:
        # Not conn.run(): asyncssh < 2.20 builds its result without fields on Python 3.14.
        process = await conn.create_process(command)
        try:
            if input:
                process.stdin.write(input)
            process.stdin.write_eof()
            stdout, stderr = await asyncio.wait_for(process.communicate(), _TIMEOUT)
        finally:
            process.close()
        if process.exit_status != 0:
            raise asyncssh.ProcessError(
                process.env, command, None, process.exit_status, process.exit_signal,
                process.returncode, stdout, stderr,
            )
        return stdout or ""

    async def _sudo(self, conn: asyncssh.SSHClientConnection, command: str) -> str:
        return await self._run(conn, f"sudo -S -p '' -- {command}", self._password + "\n")

    async def read_file(self, path: str) -> str:
        async with await self._connect() as conn:
            return await self._sudo(conn, f"cat -- {quote(path)}")

    async def write_file(self, path: str, content: str) -> None:
        async with await self._connect() as conn:
            staged = quote((await self._run(conn, "mktemp")).strip())
            try:
                await self._run(conn, f"cat > {staged}", content)
                await self._install_file(conn, staged, quote(path))
            finally:
                try:
                    await self._run(conn, f"rm -f -- {staged}")
                except (OSError, asyncssh.Error):
                    _LOGGER.debug("Could not remove the SSH staging file")

    async def _install_file(
        self, conn: asyncssh.SSHClientConnection, staged: str, path: str,
    ) -> None:
        await self._sudo(conn, f"cp -- {staged} {path}")
