import os
import stat
import unittest
from pathlib import Path

from layers.layer4_ai import AIEnhancement
from modules.integration.external_tools import AFLWrapper


class SecurityRegressionTests(unittest.TestCase):
    def test_local_ai_probe_rejects_non_loopback_url(self):
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
