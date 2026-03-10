"""Base entity for the AdGuard Whitelist integration."""
from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AdGuardWhitelistCoordinator


class AdGuardWhitelistEntity(CoordinatorEntity[AdGuardWhitelistCoordinator]):
    """Base class for all AdGuard Whitelist entities."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: AdGuardWhitelistCoordinator, client_ip: str) -> None:
        super().__init__(coordinator)
        self._client_ip = client_ip

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._client_ip)},
            name=f"Filtrage DNS {self._client_ip}",
            manufacturer="AdGuard Home",
            model="Liste blanche",
        )
