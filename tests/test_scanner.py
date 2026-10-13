import unittest

from cloudsentry.scanner import parse_resources, scan_source


class ScannerTests(unittest.TestCase):
    def test_finds_intentionally_insecure_example(self):
        from pathlib import Path
        source = Path("examples/insecure/main.tf").read_text(encoding="utf-8")
        findings = scan_source(source)
        self.assertEqual({"CS-AWS-001", "CS-AWS-002", "CS-AWS-003", "CS-AWS-004", "CS-AWS-006"},
                         {item.rule_id for item in findings})

    def test_ignores_comments_and_safe_configuration(self):
        source = '''# resource "aws_db_instance" "fake" {\nresource "aws_ebs_volume" "safe" {\n  encrypted = true\n}\n'''
        self.assertEqual([], scan_source(source))

    def test_nested_braces_do_not_end_resource_early(self):
        resources = parse_resources('resource "aws_security_group" "web" {\n ingress {\n from_port = 22\n }\n}\n')
        self.assertEqual(1, len(resources))
        self.assertEqual(1, resources[0].start_line)

    def test_ignores_public_ssh_when_source_is_restricted(self):
        source = '''resource "aws_security_group" "admin" {\n ingress {\n from_port = 22\n to_port = 22\n cidr_blocks = ["10.0.0.0/8"]\n }\n}\n'''
        self.assertEqual([], scan_source(source))

    def test_detects_public_ipv6_ssh_rule(self):
        source = '''resource "aws_security_group" "admin" {\n ingress {\n from_port = 22\n ipv6_cidr_blocks = ["::/0"]\n }\n}\n'''
        self.assertIn("CS-AWS-003", {item.rule_id for item in scan_source(source)})


if __name__ == "__main__":
    unittest.main()

