"""Config flow for AdGuard Whitelist integration."""
from __future__ import annotations

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import SelectSelector, SelectSelectorConfig

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
)

STEP_BACKEND_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_BACKEND, default=BACKEND_ADGUARD): SelectSelector(
            SelectSelectorConfig(
                options=[
                    {"value": BACKEND_ADGUARD, "label": "AdGuard Home"},
                    {"value": BACKEND_DNSMASQ, "label": "dnsmasq (SSH local)"},
                ],
                translation_key="backend",
            )
        ),
    }
)

STEP_ADGUARD_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_ADGUARD_URL): str,
        vol.Required(CONF_ADGUARD_USER, default="admin"): str,
        vol.Required(CONF_ADGUARD_PASSWORD): str,
        vol.Required(CONF_CLIENT_IP): str,
    }
)

STEP_SSH_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_SSH_ENABLED, default=False): bool,
        vol.Optional(CONF_SSH_HOST): str,
        vol.Optional(CONF_SSH_PORT, default=22): int,
        vol.Optional(CONF_SSH_USER): str,
        vol.Optional(CONF_SSH_PASSWORD): str,
    }
)

STEP_DNSMASQ_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_SSH_HOST): str,
        vol.Optional(CONF_SSH_HOST_VPN): str,
        vol.Required(CONF_SSH_PORT, default=22): int,
        vol.Required(CONF_SSH_USER): str,
        vol.Required(CONF_SSH_PASSWORD): str,
        vol.Required(CONF_DNSMASQ_CONF_PATH, default=DEFAULT_DNSMASQ_CONF_PATH): str,
        vol.Required(CONF_UPSTREAM_DNS, default=DEFAULT_UPSTREAM_DNS): str,
        vol.Required(CONF_FIREFOX_SYNC, default=True): bool,
    }
)


class AdGuardWhitelistConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for AdGuard Whitelist."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize."""
        self._data: dict = {}

    async def async_step_user(
        self, user_input: dict[str, str] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Step 1: Choose backend."""
        if user_input is not None:
            self._data[CONF_BACKEND] = user_input[CONF_BACKEND]
            if user_input[CONF_BACKEND] == BACKEND_DNSMASQ:
                return await self.async_step_dnsmasq()
            return await self.async_step_adguard()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_BACKEND_SCHEMA,
        )

    async def async_step_adguard(
        self, user_input: dict[str, str] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Step 2a: AdGuard Home connection."""
        errors: dict[str, str] = {}

        if user_input is not None:
            from .api import AdGuardHomeAPI

            session = async_get_clientsession(self.hass, verify_ssl=False)
            api = AdGuardHomeAPI(
                user_input[CONF_ADGUARD_URL],
                user_input[CONF_ADGUARD_USER],
                user_input[CONF_ADGUARD_PASSWORD],
                session,
            )
            ok, error_key = await api.test_connection()
            if ok:
                self._data.update(user_input)
                return await self.async_step_ssh()
            errors["base"] = error_key

        return self.async_show_form(
            step_id="adguard",
            data_schema=STEP_ADGUARD_SCHEMA,
            errors=errors,
        )

    async def async_step_ssh(
        self, user_input: dict[str, str] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Step 3a: Optional SSH for Firefox bookmarks (AdGuard mode)."""
        if user_input is not None:
            self._data.update(user_input)
            if not user_input.get(CONF_SSH_ENABLED):
                self._data.pop(CONF_SSH_HOST, None)
                self._data.pop(CONF_SSH_PORT, None)
                self._data.pop(CONF_SSH_USER, None)
                self._data.pop(CONF_SSH_PASSWORD, None)

            client_ip = self._data[CONF_CLIENT_IP]
            await self.async_set_unique_id(f"adguard_whitelist_{client_ip}")
            self._abort_if_unique_id_configured()
            return self.async_create_entry(
                title=f"Sites autorisés - {client_ip}",
                data=self._data,
            )

        return self.async_show_form(
            step_id="ssh",
            data_schema=STEP_SSH_SCHEMA,
        )

    async def async_step_dnsmasq(
        self, user_input: dict[str, str] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Step 2b: dnsmasq SSH connection."""
        errors: dict[str, str] = {}

        if user_input is not None:
            from .dnsmasq import DnsmasqSSH

            client = DnsmasqSSH(
                host=user_input[CONF_SSH_HOST],
                port=user_input[CONF_SSH_PORT],
                username=user_input[CONF_SSH_USER],
                password=user_input[CONF_SSH_PASSWORD],
                conf_path=user_input.get(CONF_DNSMASQ_CONF_PATH, DEFAULT_DNSMASQ_CONF_PATH),
                upstream_dns=user_input.get(CONF_UPSTREAM_DNS, DEFAULT_UPSTREAM_DNS),
                host_vpn=user_input.get(CONF_SSH_HOST_VPN) or None,
            )
            ok, error_key = await client.test_connection()
            if ok:
                self._data.update(user_input)
                # SSH is always enabled in dnsmasq mode
                self._data[CONF_SSH_ENABLED] = True

                ssh_host = self._data[CONF_SSH_HOST]
                await self.async_set_unique_id(f"adguard_whitelist_dnsmasq_{ssh_host}")
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=f"Sites autorisés - dnsmasq ({ssh_host})",
                    data=self._data,
                )
            errors["base"] = error_key

        return self.async_show_form(
            step_id="dnsmasq",
            data_schema=STEP_DNSMASQ_SCHEMA,
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> AdGuardWhitelistOptionsFlow:
        """Get the options flow handler."""
        return AdGuardWhitelistOptionsFlow(config_entry)


class AdGuardWhitelistOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow (edit credentials after setup)."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._entry = config_entry
        self._updated: dict = {}

    @property
    def _backend(self) -> str:
        return self._entry.data.get(CONF_BACKEND, BACKEND_ADGUARD)

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Route to correct options step based on backend."""
        if self._backend == BACKEND_DNSMASQ:
            return await self.async_step_dnsmasq(user_input)
        return await self.async_step_adguard(user_input)

    async def async_step_adguard(
        self, user_input: dict[str, str] | None = None
    ) -> config_entries.ConfigFlowResult:
        """AdGuard Home settings."""
        if user_input is not None:
            self._updated = user_input
            return await self.async_step_ssh()

        current = self._entry.data
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_ADGUARD_URL,
                    default=current.get(CONF_ADGUARD_URL, ""),
                ): str,
                vol.Required(
                    CONF_ADGUARD_USER,
                    default=current.get(CONF_ADGUARD_USER, ""),
                ): str,
                vol.Required(
                    CONF_ADGUARD_PASSWORD,
                    default=current.get(CONF_ADGUARD_PASSWORD, ""),
                ): str,
                vol.Required(
                    CONF_CLIENT_IP,
                    default=current.get(CONF_CLIENT_IP, ""),
                ): str,
            }
        )
        return self.async_show_form(step_id="adguard", data_schema=schema)

    async def async_step_ssh(
        self, user_input: dict[str, str] | None = None
    ) -> config_entries.ConfigFlowResult:
        """SSH settings (AdGuard mode)."""
        if user_input is not None:
            data = {**self._entry.data, **self._updated, **user_input}
            if not user_input.get(CONF_SSH_ENABLED):
                data.pop(CONF_SSH_HOST, None)
                data.pop(CONF_SSH_PORT, None)
                data.pop(CONF_SSH_USER, None)
                data.pop(CONF_SSH_PASSWORD, None)
            self.hass.config_entries.async_update_entry(self._entry, data=data)
            await self.hass.config_entries.async_reload(self._entry.entry_id)
            return self.async_create_entry(title="", data={})

        current = self._entry.data
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_SSH_ENABLED,
                    default=current.get(CONF_SSH_ENABLED, False),
                ): bool,
                vol.Required(
                    CONF_SSH_HOST,
                    default=current.get(CONF_SSH_HOST, ""),
                ): str,
                vol.Required(
                    CONF_SSH_PORT,
                    default=current.get(CONF_SSH_PORT, 22),
                ): int,
                vol.Required(
                    CONF_SSH_USER,
                    default=current.get(CONF_SSH_USER, ""),
                ): str,
                vol.Required(
                    CONF_SSH_PASSWORD,
                    default=current.get(CONF_SSH_PASSWORD, ""),
                ): str,
            }
        )
        return self.async_show_form(step_id="ssh", data_schema=schema)

    async def async_step_dnsmasq(
        self, user_input: dict[str, str] | None = None
    ) -> config_entries.ConfigFlowResult:
        """dnsmasq settings."""
        if user_input is not None:
            data = {**self._entry.data, **user_input}
            self.hass.config_entries.async_update_entry(self._entry, data=data)
            await self.hass.config_entries.async_reload(self._entry.entry_id)
            return self.async_create_entry(title="", data={})

        current = self._entry.data
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_SSH_HOST,
                    default=current.get(CONF_SSH_HOST, ""),
                ): str,
                vol.Optional(
                    CONF_SSH_HOST_VPN,
                    description={"suggested_value": current.get(CONF_SSH_HOST_VPN, "")},
                ): str,
                vol.Required(
                    CONF_SSH_PORT,
                    default=current.get(CONF_SSH_PORT, 22),
                ): int,
                vol.Required(
                    CONF_SSH_USER,
                    default=current.get(CONF_SSH_USER, ""),
                ): str,
                vol.Required(
                    CONF_SSH_PASSWORD,
                    default=current.get(CONF_SSH_PASSWORD, ""),
                ): str,
                vol.Required(
                    CONF_DNSMASQ_CONF_PATH,
                    default=current.get(CONF_DNSMASQ_CONF_PATH, DEFAULT_DNSMASQ_CONF_PATH),
                ): str,
                vol.Required(
                    CONF_UPSTREAM_DNS,
                    default=current.get(CONF_UPSTREAM_DNS, DEFAULT_UPSTREAM_DNS),
                ): str,
                vol.Required(
                    CONF_FIREFOX_SYNC,
                    default=current.get(CONF_FIREFOX_SYNC, True),
                ): bool,
            }
        )
        return self.async_show_form(step_id="dnsmasq", data_schema=schema)
