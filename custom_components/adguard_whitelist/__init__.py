"""AdGuard Whitelist — manage allowed sites from Home Assistant."""
from __future__ import annotations

import logging
import shutil
from pathlib import Path

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    BACKEND_ADGUARD,
    BACKEND_DNSMASQ,
    CONF_ADGUARD_PASSWORD,
    CONF_ADGUARD_URL,
    CONF_ADGUARD_USER,
    CONF_BACKEND,
    CONF_CLIENT_IP,
    CONF_DNSMASQ_CONF_PATH,
    CONF_FIREFOX_SYNC,
    CONF_SSH_ENABLED,
    CONF_SSH_HOST,
    CONF_SSH_HOST_VPN,
    CONF_SSH_PASSWORD,
    CONF_SSH_PORT,
    CONF_SSH_USER,
    CONF_UPSTREAM_DNS,
    DEFAULT_DNSMASQ_CONF_PATH,
    DEFAULT_UPSTREAM_DNS,
    DOMAIN,
    SERVICE_ADD_BOOKMARK,
    SERVICE_ADD_SITE,
    SERVICE_REMOVE_SITE,
)
from .coordinator import AdGuardWhitelistCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.SENSOR, Platform.SWITCH]

CARD_JS = "adguard-whitelist-card.js"

_CARD_REGISTERED = False


def _get_version() -> str:
    """Read version from manifest.json for cache-busting."""
    import json

    manifest = Path(__file__).parent / "manifest.json"
    try:
        return json.loads(manifest.read_text()).get("version", "0")
    except Exception:
        return "0"


def _deploy_card(hass: HomeAssistant) -> None:
    """Copy card JS to www/ (loaded via Lovelace resources)."""
    global _CARD_REGISTERED
    if _CARD_REGISTERED:
        return

    src = Path(__file__).parent / "www" / CARD_JS
    dst_dir = Path(hass.config.path("www"))
    dst_dir.mkdir(exist_ok=True)
    dst = dst_dir / CARD_JS
    try:
        shutil.copy2(str(src), str(dst))
        version = _get_version()
        _LOGGER.info("AdGuard Whitelist card v%s deployed to %s", version, dst)
    except Exception:
        _LOGGER.warning("Could not copy card JS from %s to %s", src, dst)

    _CARD_REGISTERED = True


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the integration domain."""
    hass.data.setdefault(DOMAIN, {})
    _deploy_card(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up AdGuard Whitelist from a config entry."""
    _deploy_card(hass)

    backend = entry.data.get(CONF_BACKEND, BACKEND_ADGUARD)
    api = None
    dnsmasq_client = None
    ssh_client = None
    # Used as device/entity identifier
    device_id = ""

    if backend == BACKEND_DNSMASQ:
        from .dnsmasq import DnsmasqSSH

        vpn_host = entry.data.get(CONF_SSH_HOST_VPN) or None
        dnsmasq_client = DnsmasqSSH(
            host=entry.data[CONF_SSH_HOST],
            port=entry.data[CONF_SSH_PORT],
            username=entry.data[CONF_SSH_USER],
            password=entry.data[CONF_SSH_PASSWORD],
            conf_path=entry.data.get(CONF_DNSMASQ_CONF_PATH, DEFAULT_DNSMASQ_CONF_PATH),
            upstream_dns=entry.data.get(CONF_UPSTREAM_DNS, DEFAULT_UPSTREAM_DNS),
            host_vpn=vpn_host,
        )
        device_id = entry.data[CONF_SSH_HOST]

        # Firefox bookmarks use same SSH connection
        if entry.data.get(CONF_FIREFOX_SYNC, True):
            from .ssh import FirefoxSSH

            ssh_client = FirefoxSSH(
                host=entry.data[CONF_SSH_HOST],
                port=entry.data[CONF_SSH_PORT],
                username=entry.data[CONF_SSH_USER],
                password=entry.data[CONF_SSH_PASSWORD],
                host_vpn=vpn_host,
            )
    else:
        from .api import AdGuardHomeAPI

        session = async_get_clientsession(hass, verify_ssl=False)
        api = AdGuardHomeAPI(
            url=entry.data[CONF_ADGUARD_URL],
            username=entry.data[CONF_ADGUARD_USER],
            password=entry.data[CONF_ADGUARD_PASSWORD],
            session=session,
        )
        device_id = entry.data[CONF_CLIENT_IP]

        # Optional SSH client for Firefox bookmarks
        if entry.data.get(CONF_SSH_ENABLED):
            from .ssh import FirefoxSSH

            ssh_client = FirefoxSSH(
                host=entry.data[CONF_SSH_HOST],
                port=entry.data[CONF_SSH_PORT],
                username=entry.data[CONF_SSH_USER],
                password=entry.data[CONF_SSH_PASSWORD],
            )

    coordinator = AdGuardWhitelistCoordinator(
        hass,
        api=api,
        dnsmasq_client=dnsmasq_client,
        client_ip=entry.data.get(CONF_CLIENT_IP, ""),
        ssh_client=ssh_client,
        backend=backend,
    )
    await coordinator.async_load_pending()
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "coordinator": coordinator,
        "device_id": device_id,
        "backend": backend,
    }

    _register_services(hass)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok


def _register_services(hass: HomeAssistant) -> None:
    """Register add_site and remove_site services."""

    async def handle_add_site(call: ServiceCall) -> None:
        domain_name = call.data["domain"].lower().strip()
        category = call.data.get("category")
        create_bookmark = call.data.get("create_bookmark", True)
        for entry_data in hass.data[DOMAIN].values():
            if not isinstance(entry_data, dict):
                continue
            coordinator: AdGuardWhitelistCoordinator = entry_data["coordinator"]
            await coordinator.async_add_domain(
                domain_name, category=category, create_bookmark=create_bookmark
            )

    async def handle_remove_site(call: ServiceCall) -> None:
        domain_name = call.data["domain"].lower().strip()
        for entry_data in hass.data[DOMAIN].values():
            if not isinstance(entry_data, dict):
                continue
            coordinator: AdGuardWhitelistCoordinator = entry_data["coordinator"]
            await coordinator.async_remove_domain(domain_name)

    async def handle_add_bookmark(call: ServiceCall) -> None:
        domain_name = call.data["domain"].lower().strip()
        for entry_data in hass.data[DOMAIN].values():
            if not isinstance(entry_data, dict):
                continue
            coordinator: AdGuardWhitelistCoordinator = entry_data["coordinator"]
            await coordinator.async_add_bookmark(domain_name)

    if not hass.services.has_service(DOMAIN, SERVICE_ADD_SITE):
        hass.services.async_register(
            DOMAIN,
            SERVICE_ADD_SITE,
            handle_add_site,
            schema=vol.Schema({
                vol.Required("domain"): str,
                vol.Optional("category"): str,
                vol.Optional("create_bookmark", default=True): bool,
            }),
        )
        hass.services.async_register(
            DOMAIN,
            SERVICE_REMOVE_SITE,
            handle_remove_site,
            schema=vol.Schema({vol.Required("domain"): str}),
        )
        hass.services.async_register(
            DOMAIN,
            SERVICE_ADD_BOOKMARK,
            handle_add_bookmark,
            schema=vol.Schema({vol.Required("domain"): str}),
        )
