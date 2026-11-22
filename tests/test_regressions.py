"""Regression checks independent of a running Home Assistant or SSH host."""

import importlib
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import AsyncMock

PACKAGE = "test_adguard_whitelist"
package = types.ModuleType(PACKAGE)
package.__path__ = [
    str(Path(__file__).resolve().parents[1] / "custom_components" / "adguard_whitelist")
]
sys.modules[PACKAGE] = package
dnsmasq = importlib.import_module(f"{PACKAGE}.dnsmasq")
rules = importlib.import_module(f"{PACKAGE}.rules")
ssh = importlib.import_module(f"{PACKAGE}.ssh_client")


class RulesTests(unittest.TestCase):
    def test_normalizes_hostname_and_rejects_invalid_domains(self):
        self.assertEqual(rules.normalize_domain(" École.FR. "), "xn--cole-9oa.fr")
        for domain in ("", "-invalid.fr", "a..fr", "example.fr/path", "a\n.invalid"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                rules.normalize_domain(domain)

    def test_preserves_existing_rules_belonging_to_other_clients(self):
        ours = "@@||Example.FR^$client=192.0.2.1"
        other = "@@||example.fr^$client='192.0.2.2'"
        existing = ["! comment", ours, other]
        self.assertEqual(rules.add_domain_to_rules(existing, "example.fr", "192.0.2.1"), existing)
        self.assertEqual(
            rules.remove_domain_from_rules(existing, "example.fr", "192.0.2.1"),
            ["! comment", other],
        )

    def test_dnsmasq_keeps_custom_upstream_and_accepts_empty_file(self):
        content = "# allowlist\nserver=/EXAMPLE.FR/8.8.8.8\n"
        self.assertEqual(dnsmasq.add_domain_to_conf(content, "example.fr", "9.9.9.9"), content)
        self.assertEqual(dnsmasq.add_domain_to_conf("", "example.fr", "9.9.9.9"),
                         "server=/example.fr/9.9.9.9\n")
        self.assertEqual(dnsmasq.remove_domain_from_conf(content, "example.fr"), "# allowlist\n")
        self.assertEqual(dnsmasq.normalize_upstream("fe80::1%eth0"), "fe80::1%eth0")
        with self.assertRaises(ValueError):
            dnsmasq.normalize_upstream("fe80::1%eth0\nnew directive")


class SSHTests(unittest.IsolatedAsyncioTestCase):
    async def test_password_and_file_use_separate_stdin_streams(self):
        conn = AsyncMock()
        conn.__aenter__.return_value = conn
        conn.run.return_value.stdout = "/tmp/staged\n"
        client = ssh.SSHClient("host", 22, "user", "test' password")
        client._connect = AsyncMock(return_value=conn)
        content = "# exact bytes\nserver=/example.fr/9.9.9.9\n"

        await client.write_file("/etc/dnsmasq.d/file with spaces", content)

        stage = conn.run.await_args_list[1]
        self.assertEqual(stage.kwargs["input"], content)
        command = conn.run.await_args_list[2]
        self.assertEqual(command.kwargs["input"], "test' password\n")
        self.assertNotIn("test' password", command.args[0])
        self.assertEqual(
            shlex.split(command.args[0])[-2:], ["/tmp/staged", "/etc/dnsmasq.d/file with spaces"]
        )
        self.assertTrue(command.kwargs["check"])

    async def test_failed_write_propagates_and_cleans_staging_file(self):
        conn = AsyncMock()
        conn.__aenter__.return_value = conn
        conn.run.return_value.stdout = "/tmp/staged\n"
        client = ssh.SSHClient("host", 22, "user", "test password")
        client._connect = AsyncMock(return_value=conn)
        client._install_file = AsyncMock(side_effect=OSError("write failed"))
        with self.assertRaisesRegex(OSError, "write failed"):
            await client.write_file("/etc/file", "new contents")
        self.assertEqual(conn.run.await_args.args, ("rm -f -- /tmp/staged",))

    async def test_empty_dnsmasq_file_is_a_valid_configuration(self):
        client = dnsmasq.DnsmasqSSH("host", 22, "user", "test password")
        client.read_file = AsyncMock(return_value="")
        self.assertEqual(await client.test_connection(), (True, ""))


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux systemctl shell regression")
class DnsmasqRollbackTests(unittest.TestCase):
    def test_restores_original_config_when_restart_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            systemctl = root / "systemctl"
            systemctl.write_text('#!/bin/sh\n[ "$(cat "$DNSMASQ_FILE")" = "original" ]\n')
            systemctl.chmod(0o755)
            original = root / "conf"
            original.write_text("original\n")
            staged = root / "staged"
            staged.write_text("updated\n")
            result = subprocess.run(
                ["sh", "-c", dnsmasq._INSTALL_CONF, "sh", str(staged), str(original)],
                env={"PATH": f"{root}:/usr/bin:/bin", "DNSMASQ_FILE": str(original)},
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(original.read_text(), "original\n")
