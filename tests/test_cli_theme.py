import unittest

from cli import main as cli_main


class CLIThemeTests(unittest.TestCase):
    def test_all_theme_presets_have_semantic_styles(self):
        required = {"banner", "accent", "success", "warning", "critical", "high", "medium", "low", "info", "muted", "label", "border", "table_header", "prompt"}
        for name, palette in cli_main.THEME_PRESETS.items():
            self.assertTrue(required.issubset(palette), name)

    def test_unknown_theme_falls_back_to_cyber(self):
        self.assertEqual(cli_main._make_theme("does-not-exist"), "cyber")

    def test_no_color_environment_flag(self):
        self.assertFalse(cli_main._no_color())


if __name__ == "__main__":
    unittest.main()
