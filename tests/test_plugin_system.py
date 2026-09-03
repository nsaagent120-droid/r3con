import json
import tempfile
import unittest
from pathlib import Path
from core.plugin_system import PluginRegistry, PluginSpec, CommandPlugin, default_registry, save_run

class PluginSystemTests(unittest.TestCase):
    def test_missing_tool_is_skipped_without_install(self):
        registry = PluginRegistry()
        registry.register(CommandPlugin(PluginSpec("missing", "test", "r3con-tool-that-does-not-exist", ["test"]), lambda t: ["r3con-tool-that-does-not-exist", t]))
        with tempfile.NamedTemporaryFile() as target:
            result = registry.run(["missing"], target.name)
        self.assertEqual(result["plugins"][0]["status"], "skipped")

    def test_default_registry_contains_historical_integrations(self):
        names = {item["name"] for item in default_registry().list()}
        self.assertTrue({"radare2", "binwalk", "ghidra", "gdb"}.issubset(names))

    def test_run_is_saved_as_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = save_run({"target": "x", "plugins": []}, directory)
            self.assertTrue(Path(path).exists())
            self.assertEqual(json.loads(Path(path).read_text())["target"], "x")

if __name__ == "__main__":
    unittest.main()
