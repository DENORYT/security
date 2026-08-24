from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from projects.pipeline_exposure import ExposureScanner, scan_path


FIXTURES = Path(__file__).parents[1] / "projects" / "pipeline_exposure" / "fixtures"


class PipelineExposureTests(unittest.TestCase):
    def test_safe_fixture_has_no_findings(self) -> None:
        findings = scan_path(FIXTURES / "safe-workflow.yml")
        self.assertEqual([], findings)

    def test_unsafe_fixture_reports_expected_risks(self) -> None:
        findings = scan_path(FIXTURES / "unsafe-workflow.yml")
        rule_ids = {finding.rule_id for finding in findings}
        self.assertTrue(
            {"pull-request-target", "write-all-permissions", "unpinned-github-action", "inline-secret-assignment", "piped-remote-script"}.issubset(rule_ids)
        )

    def test_output_redacts_detected_values(self) -> None:
        findings = scan_path(FIXTURES / "unsafe-workflow.yml")
        excerpts = "\n".join(finding.excerpt for finding in findings)
        self.assertNotIn("not-a-real-secret", excerpts)
        self.assertIn("<redacted>", excerpts)

    def test_findings_are_sorted_for_stable_ci_output(self) -> None:
        findings = scan_path(FIXTURES)
        observed = [(item.path, item.line, item.rule_id) for item in findings]
        self.assertEqual(sorted(observed), observed)

    def test_explicit_file_gate_scans_source_and_documentation_suffixes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            changed_document = Path(temporary_directory) / "notes.md"
            changed_document.write_text("token=not-a-real-secret", encoding="utf-8")
            findings = ExposureScanner().scan_files([changed_document], display_root=temporary_directory)
        self.assertEqual(["inline-secret-assignment"], [finding.rule_id for finding in findings])


if __name__ == "__main__":
    unittest.main()
