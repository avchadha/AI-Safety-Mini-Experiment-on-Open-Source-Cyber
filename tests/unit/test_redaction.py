import unittest

from cyberdetect.telemetry.redact import EpisodeRedactor


class RedactionTests(unittest.TestCase):
    def test_pseudonyms_are_stable_and_namespaced(self) -> None:
        redactor = EpisodeRedactor(b"secret-key")
        self.assertEqual(redactor.pseudonym("user", "alice"), redactor.pseudonym("user", "alice"))
        self.assertNotEqual(redactor.pseudonym("user", "alice"), redactor.pseudonym("resource", "alice"))

    def test_resource_path_is_redacted(self) -> None:
        redactor = EpisodeRedactor(b"secret-key")
        original = "/api/resources/res_private"
        redacted = redactor.path(original, ["res_private"])
        self.assertNotIn("res_private", redacted)
        self.assertIn("/api/resources/res_", redacted)


if __name__ == "__main__":
    unittest.main()

