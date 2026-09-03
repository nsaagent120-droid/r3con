import subprocess
import tempfile
import unittest
from unittest.mock import patch

from core.plugin_system import CommandPlugin, PluginSpec
from modules.integration.reverse_adapters import GhidraAdapter, R2Adapter
from modules.orchestration.orchestrator import Orchestrator


class PluginHardeningTests(unittest.TestCase):
    def test_command_plugin_timeout_is_structured(self):
        plugin = CommandPlugin(
            PluginSpec("fake", "fake", "fake-tool", ["test"]),
            lambda target: ["fake-tool", target],
        )
        with tempfile.NamedTemporaryFile() as target, patch.object(plugin, "available", return_value=True), \
             patch("core.plugin_system.subprocess.run", side_effect=subprocess.TimeoutExpired(["fake-tool"], 1)):
            result = plugin.run(target.name, timeout=1)
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["findings"], [])

    def test_command_plugin_absent_is_skipped(self):
        plugin = CommandPlugin(
            PluginSpec("missing", "missing", "definitely-not-installed", ["test"]),
            lambda target: ["definitely-not-installed", target],
        )
        with tempfile.NamedTemporaryFile() as target:
            result = plugin.run(target.name)
        self.assertEqual(result["status"], "skipped")

    def test_reverse_adapters_report_unsupported_without_tool(self):
        with patch("modules.integration.reverse_adapters.shutil.which", return_value=None):
            self.assertEqual(R2Adapter("sample.bin").analyze()["status"], "unsupported")
            self.assertEqual(GhidraAdapter("sample.bin").analyze()["status"], "unsupported")

    def test_orchestrator_rejects_missing_and_oversized_targets(self):
        missing = Orchestrator("/does/not/exist", max_mb=1).run()
        self.assertEqual(missing["status"], "invalid")
        with tempfile.NamedTemporaryFile() as target:
            target.write(b"x" * (1024 * 1024 + 1))
            target.flush()
            result = Orchestrator(target.name, max_mb=1, cache=False).run()
        self.assertEqual(result["status"], "invalid")


if __name__ == "__main__":
    unittest.main()
