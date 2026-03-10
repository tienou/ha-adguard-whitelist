"""AdGuard Whitelist — manage allowed sites from Home Assistant."""
from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path

import voluptuous as vol

from homeassistant.components.frontend import add_extra_js_url
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AdGuardHomeAPI
from .const import (
    CONF_ADGUARD_PASSWORD,
    CONF_ADGUARD_URL,
    CONF_ADGUARD_USER,
    CONF_CLIENT_IP,
    CONF_SSH_ENABLED,
    CONF_SSH_HOST,
    CONF_SSH_PASSWORD,
    CONF_SSH_PORT,
    CONF_SSH_USER,
    DOMAIN,
    SERVICE_ADD_SITE,
    SERVICE_REMOVE_SITE,
)
from .coordinator import AdGuardWhitelistCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.SENSOR, Platform.SWITCH]

CARD_JS = "adguard-whitelist-card.js"
# Serve directly from integration dir — no copy to www/ needed
CARD_URL = f"/{DOMAIN}/{CARD_JS}"

_CARD_REGISTERED = False


async def _register_card(hass: HomeAssistant) -> None:
    """Serve card JS from integration dir and register as Lovelace resource."""
    global _CARD_REGISTERED
    if _CARD_REGISTERED:
        return

    www_dir = str(Path(__file__).parent / "www")

    # Serve the www/ folder at /adguard_whitelist/
    try:
        from homeassistant.components.http import StaticPathConfig

        await hass.http.async_register_static_paths(
            [StaticPathConfig(f"/{DOMAIN}", www_dir, cache_headers=False)]
        )
    except (ImportError, AttributeError):
        hass.http.register_static_path(f"/{DOMAIN}", www_dir, False)

    _LOGGER.info("Card JS served at %s", CARD_URL)

    # Load JS on every HA page
    add_extra_js_url(hass, CARD_URL)

    # Register in .storage/lovelace_resources (persists across restarts)
    try:
        added = await hass.async_add_executor_job(
            _ensure_lovelace_storage, hass
        )
        if added:
            _LOGGER.info("Lovelace resource written to storage: %s", CARD_URL)
    except Exception as err:
        _LOGGER.warning("Could not write Lovelace storage: %s", err)

    # Also try in-memory registration (for current session)
    try:
        resources = hass.data.get("lovelace", {}).get("resources")
        if resources is not None:
            existing = [
                r for r in resources.async_items()
                if CARD_JS in r.get("url", "")
            ]
            if not existing:
                await resources.async_create_item(
                    {"res_type": "module", "url": CARD_URL}
                )
                _LOGGER.info("Lovelace resource registered in memory")
    except Exception:
        _LOGGER.debug("In-memory registration skipped", exc_info=True)

    _CARD_REGISTERED = True


def _ensure_lovelace_storage(hass: HomeAssistant) -> bool:
    """Write card URL directly into .storage/lovelace_resources (sync)."""
    storage_path = Path(hass.config.path(".storage")) / "lovelace_resources"

    if storage_path.exists():
        with open(storage_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = {
            "version": 1,
            "minor_version": 1,
            "key": "lovelace_resources",
            "data": {"items": []},
        }

    items = data.get("data", {}).get("items", [])

    for item in items:
        if CARD_JS in item.get("url", ""):
            return False

    items.append({
        "id": uuid.uuid4().hex[:12],
        "type": "module",
        "url": CARD_URL,
    })
    data["data"]["items"] = items

    storage_path.parent.mkdir(parents=True, exist_ok=True)
    with open(storage_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)

    return True


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the integration domain."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up AdGuard Whitelist from a config entry."""
    await _register_card(hass)
    session = async_get_clientsession(hass)
    api = AdGuardHomeAPI(
        url=entry.data[CONF_ADGUARD_URL],
        username=entry.data[CONF_ADGUARD_USER],
        password=entry.data[CONF_ADGUARD_PASSWORD],
        session=session,
    )

    # Optional SSH client for Firefox bookmarks
    ssh_client = None
    if entry.data.get(CONF_SSH_ENABLED):
        from .ssh import FirefoxSSH

        ssh_client = FirefoxSSH(
            host=entry.data[CONF_SSH_HOST],
            port=entry.data[CONF_SSH_PORT],
            username=entry.data[CONF_SSH_USER],
            password=entry.data[CONF_SSH_PASSWORD],
        )

    coordinator = AdGuardWhitelistCoordinator(
        hass, api, entry.data[CONF_CLIENT_IP], ssh_client
    )
    await coordinator.async_load_pending()
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "coordinator": coordinator,
        "api": api,
        "client_ip": entry.data[CONF_CLIENT_IP],
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
        for entry_data in hass.data[DOMAIN].values():
            if not isinstance(entry_data, dict):
                continue
            coordinator: AdGuardWhitelistCoordinator = entry_data["coordinator"]
            await coordinator.async_add_domain(domain_name)

    async def handle_remove_site(call: ServiceCall) -> None:
        domain_name = call.data["domain"].lower().strip()
        for entry_data in hass.data[DOMAIN].values():
            if not isinstance(entry_data, dict):
                continue
            coordinator: AdGuardWhitelistCoordinator = entry_data["coordinator"]
            await coordinator.async_remove_domain(domain_name)

    if not hass.services.has_service(DOMAIN, SERVICE_ADD_SITE):
        hass.services.async_register(
            DOMAIN,
            SERVICE_ADD_SITE,
            handle_add_site,
            schema=vol.Schema({vol.Required("domain"): str}),
        )
        hass.services.async_register(
            DOMAIN,
            SERVICE_REMOVE_SITE,
            handle_remove_site,
            schema=vol.Schema({vol.Required("domain"): str}),
        )
