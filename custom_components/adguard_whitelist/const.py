"""Constants for the AdGuard Whitelist integration."""

DOMAIN = "adguard_whitelist"

# Backend choice
CONF_BACKEND = "backend"
BACKEND_ADGUARD = "adguard"
BACKEND_DNSMASQ = "dnsmasq"

# AdGuard Home
CONF_ADGUARD_URL = "adguard_url"
CONF_ADGUARD_USER = "adguard_user"
CONF_ADGUARD_PASSWORD = "adguard_password"
CONF_CLIENT_IP = "client_ip"

# SSH (shared by Firefox + dnsmasq)
CONF_SSH_ENABLED = "ssh_enabled"
CONF_SSH_HOST = "ssh_host"
CONF_SSH_HOST_VPN = "ssh_host_vpn"
CONF_SSH_PORT = "ssh_port"
CONF_SSH_USER = "ssh_user"
CONF_SSH_PASSWORD = "ssh_password"

# dnsmasq-specific
CONF_DNSMASQ_CONF_PATH = "dnsmasq_conf_path"
CONF_UPSTREAM_DNS = "upstream_dns"
CONF_FIREFOX_SYNC = "firefox_sync"
DEFAULT_DNSMASQ_CONF_PATH = "/etc/dnsmasq.d/whitelist-camille.conf"
DEFAULT_UPSTREAM_DNS = "9.9.9.9"

FIREFOX_POLICIES_PATH = "/usr/lib/firefox/distribution/policies.json"

SCAN_INTERVAL_SECONDS = 120

SERVICE_ADD_SITE = "add_site"
SERVICE_REMOVE_SITE = "remove_site"
SERVICE_ADD_BOOKMARK = "add_bookmark"

EDUCATIONAL_SITES: dict[str, str] = {
    "lumni.fr": "Éducation",
    "logicieleducatif.fr": "Éducation",
    "calculatice.ac-lille.fr": "Éducation",
    "khanacademy.org": "Éducation",
    "fr.khanacademy.org": "Éducation",
    "bescherelle.com": "Éducation",
    "scratch.mit.edu": "Programmation",
    "mathador.fr": "Éducation",
    "lalilo.com": "Éducation",
}

CDN_PATTERNS: list[str] = [
    "cdn.",
    "static.",
    "assets.",
    "cloudfront.net",
    "googleapis.com",
    "gstatic.com",
    "cloudflare.com",
    "jsdelivr.net",
    "unpkg.com",
    "kastatic.org",
    "s3.amazonaws.com",
]
