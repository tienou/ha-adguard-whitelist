"""Base entity for the AdGuard Whitelist integration."""
from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import BACKEND_DNSMASQ, DOMAIN
from .coordinator import AdGuardWhitelistCoordinator


class AdGuardWhitelistEntity(CoordinatorEntity[AdGuardWhitelistCoordinator]):
    """Base class for all AdGuard Whitelist entities."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AdGuardWhitelistCoordinator,
        device_id: str,
        backend: str = "adguard",
    ) -> None:
        super().__init__(coordinator)
        self._device_id = device_id
        self._backend = backend

    @property
    def device_info(self) -> DeviceInfo:
        if self._backend == BACKEND_DNSMASQ:
            return DeviceInfo(
                identifiers={(DOMAIN, self._device_id)},
                name=f"Filtrage DNS {self._device_id}",
                manufacturer="dnsmasq",
                model="Liste blanche (SSH)",
            )
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            name=f"Filtrage DNS {self._device_id}",
            manufacturer="AdGuard Home",
            model="Liste blanche",
        )
