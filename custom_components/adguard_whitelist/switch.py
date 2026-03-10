"""Switch platform for AdGuard Whitelist — one toggle per allowed site."""
from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import AdGuardWhitelistCoordinator
from .entity import AdGuardWhitelistEntity
from .rules import categorize_domain


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up dynamic per-site switches."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: AdGuardWhitelistCoordinator = data["coordinator"]
    client_ip: str = data["client_ip"]

    current_switches: dict[str, AdGuardSiteSwitch] = {}

    @callback
    def _update_switches() -> None:
        """Sync switch entities with the current domain list."""
        domains = set(coordinator.data.get("domains", []))
        existing = set(current_switches.keys())

        # Add new switches
        new_domains = domains - existing
        if new_domains:
            new_entities = []
            for domain in sorted(new_domains):
                sw = AdGuardSiteSwitch(coordinator, client_ip, domain, entry)
                current_switches[domain] = sw
                new_entities.append(sw)
            async_add_entities(new_entities)

        # Remove stale switches
        stale_domains = existing - domains
        for domain in stale_domains:
            sw = current_switches.pop(domain)
            hass.async_create_task(sw.async_remove())

    # Initial population
    _update_switches()

    # Listen for coordinator updates
    coordinator.async_add_listener(_update_switches)


class AdGuardSiteSwitch(AdGuardWhitelistEntity, SwitchEntity):
    """Toggle switch for a single whitelisted domain."""

    _attr_icon = "mdi:web"

    def __init__(
        self,
        coordinator: AdGuardWhitelistCoordinator,
        client_ip: str,
        domain: str,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator, client_ip)
        self._domain = domain
        self._attr_unique_id = f"{entry.entry_id}_site_{domain.replace('.', '_')}"
        self._attr_name = domain
        self._attr_extra_state_attributes = {"category": categorize_domain(domain)}

    @property
    def is_on(self) -> bool:
        """ON means the domain is in the whitelist."""
        return self._domain in self.coordinator.data.get("domains", [])

    async def async_turn_off(self, **kwargs) -> None:
        """Remove the domain from the whitelist."""
        await self.coordinator.async_remove_domain(self._domain)

    async def async_turn_on(self, **kwargs) -> None:
        """Re-add the domain to the whitelist."""
        await self.coordinator.async_add_domain(self._domain)
