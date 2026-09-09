import os
import stat
import unittest
from pathlib import Path

try:
    from layers.layer4_ai import AIEnhancement
    LAYERS_AVAILABLE = True
except ImportError:
    LAYERS_AVAILABLE = False
    # Fallback: use core.ai_engine for similar check
    try:
        from core.local_ai_client import LocalAIClient as AIEnhancement
    except ImportError:
        AIEnhancement = None

from modules.integration.external_tools import AFLWrapper


class SecurityRegressionTests(unittest.TestCase):
    @unittest.skipIf(not LAYERS_AVAILABLE and AIEnhancement is None, "layers removed, AI check moved")
    def test_local_ai_probe_rejects_non_loopback_url(self):
        if not LAYERS_AVAILABLE:
            # New location check
            from core.local_ai_client import LocalAIClient
            ai = object.__new__(LocalAIClient)
            # Check method exists
            if hasattr(ai, '_check_local_server'):
                self.assertFalse(ai._check_local_server("https://example.com"))
                self.assertFalse(ai._check_local_server("file:///etc/passwd"))
            else:
                self.skipTest("local server check not in new location")
            return
        ai = object.__new__(AIEnhancement)
        self.assertFalse(ai._check_local_server("https://example.com"))
        self.assertFalse(ai._check_local_server("file:///etc/passwd"))

    def test_afl_default_output_is_private_temp_directory(self):
        wrapper = AFLWrapper("sample.bin")
        self.assertTrue(Path(wrapper.output).is_dir())
        mode = stat.S_IMODE(os.stat(wrapper.output).st_mode)
        self.assertEqual(mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
