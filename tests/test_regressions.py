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

import asyncssh

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


class LocalSSHServer(asyncssh.SSHServer):
    def begin_auth(self, username):
        return False


async def local_ssh_server(serve):
    return await asyncssh.listen(
        "127.0.0.1",
        0,
        server_factory=LocalSSHServer,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        process_factory=serve,
    )


class SSHTests(unittest.IsolatedAsyncioTestCase):
    async def test_dnsmasq_reads_an_actual_ssh_command_result(self):
        async def serve(process):
            self.assertEqual(process.command, "sudo -S -p '' -- cat -- /etc/test.conf")
            self.assertEqual(await process.stdin.read(), "fixture-password\n")
            process.stdout.write("server=/example.fr/9.9.9.9\n")
            process.exit(0)

        async with await local_ssh_server(serve) as server:
            client = dnsmasq.DnsmasqSSH(
                "127.0.0.1", server.get_port(), "fixture", "fixture-password",
                conf_path="/etc/test.conf",
            )
            self.assertEqual(await client.get_domains(), ["example.fr"])

    async def test_failed_remote_command_raises_process_error(self):
        async def serve(process):
            await process.stdin.read()
            process.stderr.write("cat: /etc/test.conf: No such file\n")
            process.exit(1)

        async with await local_ssh_server(serve) as server:
            client = dnsmasq.DnsmasqSSH(
                "127.0.0.1", server.get_port(), "fixture", "fixture-password",
                conf_path="/etc/test.conf",
            )
            self.assertEqual(await client.test_connection(), (False, "conf_not_found"))

    async def test_password_and_file_use_separate_stdin_streams(self):
        commands = []

        async def serve(process):
            stdin = await process.stdin.read()
            commands.append((process.command, stdin))
            if process.command == "mktemp":
                process.stdout.write("/tmp/staged\n")
            process.exit(0)

        content = "# exact bytes\nserver=/example.fr/9.9.9.9\n"
        async with await local_ssh_server(serve) as server:
            client = ssh.SSHClient("127.0.0.1", server.get_port(), "user", "test' password")
            await client.write_file("/etc/dnsmasq.d/file with spaces", content)

        self.assertEqual(commands[1], ("cat > /tmp/staged", content))
        install, password = commands[2]
        self.assertEqual(password, "test' password\n")
        self.assertNotIn("test' password", install)
        self.assertEqual(
            shlex.split(install)[-2:], ["/tmp/staged", "/etc/dnsmasq.d/file with spaces"]
        )
        self.assertEqual(commands[3], ("rm -f -- /tmp/staged", ""))

    async def test_failed_write_propagates_and_cleans_staging_file(self):
        conn = AsyncMock()
        conn.__aenter__.return_value = conn
        client = ssh.SSHClient("host", 22, "user", "test password")
        client._connect = AsyncMock(return_value=conn)
        client._run = AsyncMock(return_value="/tmp/staged\n")
        client._install_file = AsyncMock(side_effect=OSError("write failed"))
        with self.assertRaisesRegex(OSError, "write failed"):
            await client.write_file("/etc/file", "new contents")
        self.assertEqual(client._run.await_args.args, (conn, "rm -f -- /tmp/staged"))

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
            systemctl.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$(cat "$DNSMASQ_FILE")" >> "$TRACE"\n'
                '[ "$(cat "$DNSMASQ_FILE")" = "original" ]\n'
            )
            systemctl.chmod(0o755)
            original = root / "conf"
            original.write_text("original\n")
            staged = root / "staged"
            staged.write_text("updated\n")
            trace = root / "restart-trace"
            result = subprocess.run(
                ["sh", "-c", dnsmasq._INSTALL_CONF, "sh", str(staged), str(original)],
                env={
                    "PATH": f"{root}:/usr/bin:/bin",
                    "DNSMASQ_FILE": str(original),
                    "TRACE": str(trace),
                },
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(original.read_text(), "original\n")
            self.assertEqual(trace.read_text(), "updated\noriginal\n")
