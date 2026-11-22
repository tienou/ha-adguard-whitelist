"""Data update coordinator for AdGuard Whitelist with offline SSH queue."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

import asyncssh

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import BACKEND_DNSMASQ, DOMAIN, SCAN_INTERVAL_SECONDS
from .rules import (
    add_domain_to_rules,
    categorize_domain,
    parse_whitelist_rules,
    remove_domain_from_rules,
)

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION = 1


class AdGuardWhitelistCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Fetch whitelist rules and manage offline queues."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        api: Any | None = None,
        dnsmasq_client: Any | None = None,
        client_ip: str = "",
        ssh_client: Any | None = None,
        backend: str = "adguard",
        entry_id: str,
        migrate_dnsmasq_store: bool = False,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
        )
        self.api = api
        self.dnsmasq_client = dnsmasq_client
        self.client_ip = client_ip
        self.ssh_client = ssh_client
        self.backend = backend

        safe_id = f"dnsmasq_{entry_id}" if self.is_dnsmasq else client_ip.replace(".", "_")
        self._store = Store(hass, STORAGE_VERSION, f"{DOMAIN}_pending_{safe_id}")
        self._meta_store = Store(hass, STORAGE_VERSION, f"{DOMAIN}_meta_{safe_id}")
        self._entry_id = entry_id
        self._migrate_dnsmasq_store = migrate_dnsmasq_store
        self._operation_lock = asyncio.Lock()
        self._rules_lock = hass.data.setdefault(f"{DOMAIN}_rules_lock", asyncio.Lock())
        self._last_dnsmasq_domains: list[str] = []

        # Firefox bookmark queue (works for both backends)
        self._pending_ssh: list[dict[str, str]] = []
        # dnsmasq operation queue (only for dnsmasq backend)
        self._pending_dnsmasq: list[dict[str, str]] = []
        # domain → {"category": str, "has_bookmark": bool}
        self._domain_meta: dict[str, dict[str, Any]] = {}

    @property
    def is_dnsmasq(self) -> bool:
        return self.backend == BACKEND_DNSMASQ

    # ── Persistent queues ──────────────────────────────────────

    async def async_load_pending(self) -> None:
        """Load queued commands and domain metadata from disk."""
        data = await self._store.async_load()
        meta = await self._meta_store.async_load()
        if self.is_dnsmasq and (data is None or meta is None):
            data, meta = await self._load_legacy_dnsmasq(data, meta)

        if isinstance(data, dict):
            self._pending_ssh = data.get("pending_ssh", [])
            self._pending_dnsmasq = data.get("pending_dnsmasq", [])
            total = len(self._pending_ssh) + len(self._pending_dnsmasq)
            if total:
                _LOGGER.info(
                    "Loaded %d pending command(s) (%d SSH, %d dnsmasq)",
                    total, len(self._pending_ssh), len(self._pending_dnsmasq),
                )

        if isinstance(meta, dict):
            self._domain_meta = meta
            _LOGGER.debug("Loaded metadata for %d domain(s)", len(self._domain_meta))

    async def _load_legacy_dnsmasq(self, data: dict | None, meta: dict | None) -> tuple:
        """Keep the shared legacy store unless its only possible owner is known."""
        async with self._rules_lock:
            legacy_store = Store(self.hass, STORAGE_VERSION, f"{DOMAIN}_pending_dnsmasq")
            legacy_meta_store = Store(self.hass, STORAGE_VERSION, f"{DOMAIN}_meta_dnsmasq")
            legacy_data = await legacy_store.async_load() or {}
            legacy_meta = await legacy_meta_store.async_load()
            if not legacy_data and not legacy_meta:
                return data, meta
            if "migration_owner" not in legacy_data:
                legacy_data["migration_owner"] = (
                    self._entry_id if self._migrate_dnsmasq_store else None
                )
                await legacy_store.async_save(legacy_data)
            if legacy_data["migration_owner"] != self._entry_id:
                return data, meta
            if data is None:
                data = {
                    "pending_ssh": legacy_data.get("pending_ssh", []),
                    "pending_dnsmasq": legacy_data.get("pending_dnsmasq", []),
                }
                await self._store.async_save(data)
            if meta is None:
                meta = legacy_meta or {}
                await self._meta_store.async_save(meta)
            return data, meta

    async def _save_pending(self) -> None:
        await self._store.async_save({
            "pending_ssh": list(self._pending_ssh),
            "pending_dnsmasq": list(self._pending_dnsmasq),
        })

    async def _save_meta(self) -> None:
        await self._meta_store.async_save(dict(self._domain_meta))

    async def _enqueue(
        self, queue: list[dict[str, str]], action: str, domain: str,
    ) -> None:
        """Persist the latest intent before trying to apply it remotely."""
        queue[:] = [cmd for cmd in queue if cmd["domain"] != domain]
        queue.append({"action": action, "domain": domain})
        await self._save_pending()

    async def _flush_pending(
        self,
        queue: list[dict[str, str]],
        add: Callable[[str], Awaitable[None]],
        remove: Callable[[str], Awaitable[None]],
        label: str,
    ) -> None:
        """Replay queued operations in order and retain any failed operation."""
        applied = 0
        for cmd in queue:
            try:
                operation = {"add": add, "remove": remove}[cmd["action"]]
                await operation(cmd["domain"])
            except asyncssh.ProcessError as err:
                _LOGGER.warning("%s operation failed (exit %s)", label, err.exit_status)
                break
            except (OSError, asyncssh.Error) as err:
                _LOGGER.debug("%s SSH unavailable: %s", label, err)
                break
            except Exception as err:
                _LOGGER.warning("%s operation remains pending: %s", label, err)
                break
            applied += 1
        if applied:
            del queue[:applied]
            await self._save_pending()

    # ── Properties ─────────────────────────────────────────────

    @property
    def pending_ssh_count(self) -> int:
        return len(self._pending_ssh)

    @property
    def pending_dnsmasq_count(self) -> int:
        return len(self._pending_dnsmasq)

    @property
    def pending_count(self) -> int:
        return len(self._pending_ssh) + len(self._pending_dnsmasq)

    @property
    def ssh_enabled(self) -> bool:
        return self.ssh_client is not None

    # ── Domain metadata ──────────────────────────────────────────

    def get_domain_meta(self, domain: str) -> dict[str, Any]:
        """Get metadata for a domain."""
        return self._domain_meta.get(domain, {})

    def get_bookmarked_domains(self) -> set[str]:
        """Return set of domains that have Firefox bookmarks."""
        return {
            d for d, m in self._domain_meta.items() if m.get("has_bookmark")
        }

    async def _sync_bookmarks_from_firefox(self) -> bool:
        """Sync bookmark metadata by reading actual Firefox bookmarks via SSH."""
        if not self.ssh_client:
            return False

        try:
            real_bookmarks = await self.ssh_client.get_existing_bookmarks()
            _LOGGER.debug(
                "Synced %d Firefox bookmarks from remote", len(real_bookmarks)
            )
            changed = False
            pending = {cmd["domain"] for cmd in self._pending_ssh}
            for domain in real_bookmarks - pending:
                meta = self._domain_meta.get(domain, {})
                if not meta.get("has_bookmark"):
                    meta["has_bookmark"] = True
                    self._domain_meta[domain] = meta
                    changed = True
            # Also clear has_bookmark for domains no longer bookmarked
            for domain, meta in list(self._domain_meta.items()):
                if meta.get("has_bookmark") and domain not in real_bookmarks | pending:
                    meta["has_bookmark"] = False
                    changed = True
            if changed:
                await self._save_meta()
            return True
        except (OSError, asyncssh.Error) as err:
            _LOGGER.debug("Cannot sync Firefox bookmarks (PC offline?): %s", err)
        except Exception as err:
            _LOGGER.warning("Error syncing Firefox bookmarks: %s", err)
        return False

    # ── Optimistic domain list ─────────────────────────────────

    def _apply_pending_dnsmasq(self, domains: list[str]) -> list[str]:
        """Apply pending dnsmasq operations to the domain list (optimistic UI).

        When the PC is offline, the last known domain list is shown with
        queued add/remove applied on top so the UI reflects user intent.
        """
        domain_set = set(domains)
        for cmd in self._pending_dnsmasq:
            if cmd["action"] == "add":
                domain_set.add(cmd["domain"])
            elif cmd["action"] == "remove":
                domain_set.discard(cmd["domain"])
        return sorted(domain_set)

    # ── Domain operations ──────────────────────────────────────

    async def async_add_domain(
        self,
        domain: str,
        category: str | None = None,
        create_bookmark: bool = True,
    ) -> None:
        """Add a whitelisted domain."""
        async with self._operation_lock:
            if self.is_dnsmasq:
                await self._enqueue(self._pending_dnsmasq, "add", domain)
            else:
                await self._update_adguard_rules(add_domain_to_rules, domain)

            meta = self._domain_meta.setdefault(domain, {})
            if category:
                meta["category"] = category
            if create_bookmark and self.ssh_client:
                await self._enqueue(self._pending_ssh, "add", domain)
                meta["has_bookmark"] = True
            await self._save_meta()
        await self.async_request_refresh()

    async def async_add_bookmark(self, domain: str) -> None:
        """Add a Firefox bookmark for an already whitelisted domain."""
        if not self.ssh_client:
            return
        async with self._operation_lock:
            await self._enqueue(self._pending_ssh, "add", domain)
            self._domain_meta.setdefault(domain, {})["has_bookmark"] = True
            await self._save_meta()
        await self.async_request_refresh()

    async def async_remove_domain(self, domain: str) -> None:
        """Remove a whitelisted domain."""
        async with self._operation_lock:
            if self.is_dnsmasq:
                await self._enqueue(self._pending_dnsmasq, "remove", domain)
            else:
                await self._update_adguard_rules(remove_domain_from_rules, domain)

            meta = self._domain_meta.pop(domain, {})
            if self.ssh_client and (
                meta.get("has_bookmark")
                or any(cmd["domain"] == domain for cmd in self._pending_ssh)
            ):
                await self._enqueue(self._pending_ssh, "remove", domain)
            await self._save_meta()
        await self.async_request_refresh()

    async def _update_adguard_rules(
        self, edit: Callable[[list[str], str, str], list[str]], domain: str,
    ) -> None:
        # AdGuard replaces the instance's entire ruleset in a single request.
        async with self._rules_lock:
            status = await self.api.get_filtering_status()
            current = status.get("user_rules", [])
            updated = edit(current, domain, self.client_ip)
            if updated != current:
                await self.api.set_rules(updated)

    # ── Coordinator refresh ─────────────────────────────────────

    async def _async_update_data(self) -> dict[str, Any]:
        """Pull current whitelist state."""
        async with self._operation_lock:
            if self.dnsmasq_client:
                await self._flush_pending(
                    self._pending_dnsmasq,
                    self.dnsmasq_client.add_domain,
                    self.dnsmasq_client.remove_domain,
                    "dnsmasq",
                )
            if self.ssh_client:
                await self._flush_pending(
                    self._pending_ssh,
                    self.ssh_client.add_bookmark,
                    self.ssh_client.remove_bookmark,
                    "Firefox",
                )
            ssh_reachable = await self._sync_bookmarks_from_firefox()
            if self.is_dnsmasq:
                return await self._update_dnsmasq(ssh_reachable)
            return await self._update_adguard(ssh_reachable)

    async def _update_dnsmasq(self, ssh_reachable: bool) -> dict[str, Any]:
        """Refresh from dnsmasq config via SSH."""
        backend_reachable = True
        try:
            self._last_dnsmasq_domains = await self.dnsmasq_client.get_domains()
        except Exception as err:
            _LOGGER.warning("Cannot reach dnsmasq via SSH: %s", err)
            backend_reachable = False

        domains = self._apply_pending_dnsmasq(self._last_dnsmasq_domains)
        categories: dict[str, list[str]] = {}
        for d in domains:
            meta = self._domain_meta.get(d, {})
            cat = meta.get("category") or categorize_domain(d)
            categories.setdefault(cat, []).append(d)

        bookmarked = sorted(self.get_bookmarked_domains())

        return {
            "domains": domains,
            "count": len(domains),
            "categories": categories,
            "all_rules_count": len(self._last_dnsmasq_domains),
            "pending_ssh": self.pending_ssh_count,
            "pending_dnsmasq": self.pending_dnsmasq_count,
            "pending_total": self.pending_count,
            "bookmarked_domains": bookmarked,
            "ssh_enabled": self.ssh_enabled,
            "backend_reachable": backend_reachable,
            "ssh_reachable": ssh_reachable,
            "backend": BACKEND_DNSMASQ,
        }

    async def _update_adguard(self, ssh_reachable: bool) -> dict[str, Any]:
        """Refresh from AdGuard Home API."""
        from .api import AdGuardConnectionError

        adguard_reachable = True
        try:
            status = await self.api.get_filtering_status()
        except AdGuardConnectionError as err:
            _LOGGER.warning("Cannot reach AdGuard Home: %s", err)
            adguard_reachable = False
            if self.data:
                prev = dict(self.data)
                prev["backend_reachable"] = False
                prev["ssh_reachable"] = ssh_reachable
                return prev
            return {
                "domains": [],
                "count": 0,
                "categories": {},
                "all_rules_count": 0,
                "pending_ssh": self.pending_ssh_count,
                "pending_dnsmasq": 0,
                "pending_total": self.pending_count,
                "bookmarked_domains": [],
                "ssh_enabled": self.ssh_enabled,
                "backend_reachable": False,
                "ssh_reachable": ssh_reachable,
                "backend": "adguard",
            }

        all_rules = status.get("user_rules", [])
        domains = parse_whitelist_rules(all_rules, self.client_ip)

        # Use user-assigned categories, fallback to auto-detect
        categories: dict[str, list[str]] = {}
        for d in domains:
            meta = self._domain_meta.get(d, {})
            cat = meta.get("category") or categorize_domain(d)
            categories.setdefault(cat, []).append(d)

        bookmarked = sorted(self.get_bookmarked_domains())

        return {
            "domains": domains,
            "count": len(domains),
            "categories": categories,
            "all_rules_count": len(all_rules),
            "pending_ssh": self.pending_ssh_count,
            "pending_dnsmasq": 0,
            "pending_total": self.pending_count,
            "bookmarked_domains": bookmarked,
            "ssh_enabled": self.ssh_enabled,
            "backend_reachable": adguard_reachable,
            "ssh_reachable": ssh_reachable,
            "backend": "adguard",
        }
