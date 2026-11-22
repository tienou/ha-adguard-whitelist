"""SSH client for managing Firefox policies.json on a remote machine."""
from __future__ import annotations

import logging

from .const import FIREFOX_POLICIES_PATH
from .firefox import (
    add_bookmark,
    get_bookmark_domains,
    parse_policies,
    remove_bookmark,
    serialize_policies,
)
from .ssh_client import SSHClient

_LOGGER = logging.getLogger(__name__)


class FirefoxSSH(SSHClient):
    """Handle SSH connections to sync Firefox bookmarks."""

    async def test_connection(self) -> bool:
        try:
            await self._read_policies()
            return True
        except Exception as err:
            _LOGGER.error("SSH test failed: %s", err)
            return False

    async def _read_policies(self) -> dict:
        """Read and parse the current policies.json."""
        raw = await self.read_file(FIREFOX_POLICIES_PATH)
        return parse_policies(raw)

    async def _write_policies(self, policies: dict) -> None:
        """Write policies.json back to the remote machine."""
        await self.write_file(FIREFOX_POLICIES_PATH, serialize_policies(policies))

    async def get_existing_bookmarks(self) -> set[str]:
        """Return the set of domains that have Firefox bookmarks."""
        policies = await self._read_policies()
        return get_bookmark_domains(policies)

    async def add_bookmark(self, domain: str) -> None:
        """Add a bookmark to Firefox policies.json."""
        policies = await self._read_policies()
        new_policies = add_bookmark(policies, domain)
        if new_policies == policies:
            return
        await self._write_policies(new_policies)
        _LOGGER.info("Firefox bookmark added: %s", domain)

    async def remove_bookmark(self, domain: str) -> None:
        """Remove a bookmark from Firefox policies.json."""
        policies = await self._read_policies()
        new_policies = remove_bookmark(policies, domain)
        if new_policies == policies:
            return
        await self._write_policies(new_policies)
        _LOGGER.info("Firefox bookmark removed: %s", domain)
