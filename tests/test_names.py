import unittest

from osint_toolkit.names import in_scope, normalize_domain, normalize_name


class NameTests(unittest.TestCase):
    def test_idna_case_root_dot_and_label_separators(self):
        for raw in ("BÜCHER.example.", "Bu\u0308cher\u3002EXAMPLE\uff61", "XN--BCHER-KVA.example"):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_domain(raw), "xn--bcher-kva.example")

    def test_scope_checks_whole_labels_after_normalization(self):
        domain = normalize_domain("bücher.example")
        for raw in ("Bücher.example", "www.Bücher.example", "*。bücher.example."):
            with self.subTest(raw=raw):
                self.assertTrue(in_scope(normalize_name(raw, allow_wildcard=True), domain))
        for raw in ("notbücher.example", "bücher.example.invalid", "*.example"):
            with self.subTest(raw=raw):
                self.assertFalse(in_scope(normalize_name(raw, allow_wildcard=True), domain))

    def test_invalid_names_and_lossy_idna(self):
        for raw in (
            "", ".", "a..example", "a.example..", " a.example", "a.example\n", "_svc.example",
            "-a.example", "a-.example", "a/b.example", "xn--abc.example", "xn--strae-oqa.example",
            "https://a.example", "stra\x1fe.example", "straße.example", "a\u200db.example",
            "ｗｗｗ.example",
            "www.*.example", "*.*.example", "a*.example", "a" * 64 + ".example",
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                normalize_name(raw, allow_wildcard=True)

    def test_domain_rejects_wildcards_and_address_literals(self):
        for raw in ("*.example.test", "192.0.2.1", "2001:db8::1", "localhost"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                normalize_domain(raw)

    def test_253_octet_limit_includes_wildcard_label(self):
        max_name = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        self.assertEqual(len(normalize_name(max_name + ".")), 253)
        max_pattern = "*." + max_name[:-2]
        self.assertEqual(normalize_name(max_pattern, allow_wildcard=True), max_pattern)
        with self.assertRaises(ValueError):
            normalize_name(max_name + "d")
        with self.assertRaises(ValueError):
            normalize_name("*." + max_name, allow_wildcard=True)
