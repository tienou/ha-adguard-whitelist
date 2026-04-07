"""Sensor platform for AdGuard Whitelist."""
from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import AdGuardWhitelistCoordinator
from .entity import AdGuardWhitelistEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensors."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: AdGuardWhitelistCoordinator = data["coordinator"]
    device_id: str = data["device_id"]
    backend: str = data["backend"]

    async_add_entities([
        AdGuardWhitelistCountSensor(coordinator, device_id, backend, entry),
    ])


class AdGuardWhitelistCountSensor(AdGuardWhitelistEntity, SensorEntity):
    """Sensor showing the number of whitelisted sites."""

    _attr_icon = "mdi:web-check"
    _attr_native_unit_of_measurement = "site(s)"

    def __init__(
        self,
        coordinator: AdGuardWhitelistCoordinator,
        device_id: str,
        backend: str,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator, device_id, backend)
        self._attr_unique_id = f"{entry.entry_id}_whitelist_count"
        self._attr_name = "Sites autorisés"

    @property
    def native_value(self) -> int:
        return self.coordinator.data.get("count", 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self.coordinator.data
        attrs: dict[str, Any] = {
            "domains": data.get("domains", []),
            "total_rules": data.get("all_rules_count", 0),
            "pending_ssh": data.get("pending_ssh", 0),
            "pending_dnsmasq": data.get("pending_dnsmasq", 0),
            "pending_total": data.get("pending_total", 0),
            "bookmarked_domains": data.get("bookmarked_domains", []),
            "ssh_enabled": data.get("ssh_enabled", False),
            "backend": data.get("backend", "adguard"),
            "backend_reachable": data.get("backend_reachable", False),
            "ssh_reachable": data.get("ssh_reachable", False),
        }
        categories = data.get("categories", {})
        for cat_name, cat_domains in categories.items():
            key = f"category_{cat_name.lower().replace(' / ', '_').replace(' ', '_')}"
            attrs[key] = cat_domains
        return attrs
