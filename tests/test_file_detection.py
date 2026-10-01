"""Comprehensive test suite for VerifyFirst File/Attachment Detection (Phase 2).

Tests cover:
  - Feature extraction (Phase 2B)
  - Detection rules (Phase 2C)
  - File scoring and classification (Phase 2D / 2E)
  - Security edge cases (Phase 2J)
  - Regression: existing URL tests unaffected (Phase 2K)
"""

import pytest

from backend.detection.file_detection.schemas import (
    FileAnalysisInput,
    FileFeatures,
    FileDetectionResult,
)
from backend.detection.file_detection.features import (
    extract_file_features,
    DANGEROUS_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    DOCUMENT_MACRO_EXTENSIONS,
    BENIGN_DOCUMENT_EXTENSIONS,
    _extract_all_extensions,
    _get_final_extension,
    _check_extension_mismatch,
    _check_suspicious_filename,
)
from backend.detection.file_detection.rules import evaluate_file_rules
from backend.detection.file_detection.scorer import (
    analyze_file_security,
    classify_file_risk_score,
)
from backend.detection.file_detection.service import analyze_file


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2B — Feature Extraction Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestExtensionExtraction:
    """Tests for _extract_all_extensions helper."""

    def test_single_extension(self):
        assert _extract_all_extensions("photo.jpg") == (".jpg",)

    def test_double_extension(self):
        assert _extract_all_extensions("invoice.pdf.exe") == (".pdf", ".exe")

    def test_triple_extension(self):
        assert _extract_all_extensions("report.pdf.zip.exe") == (".pdf", ".zip", ".exe")

    def test_no_extension(self):
        assert _extract_all_extensions("README") == ()

    def test_dotfile(self):
        assert _extract_all_extensions(".gitignore") == (".gitignore",)

    def test_case_normalization(self):
        assert _extract_all_extensions("document.PDF.EXE") == (".pdf", ".exe")

    def test_empty_string(self):
        assert _extract_all_extensions("") == ()

    def test_path_with_directory(self):
        assert _extract_all_extensions("path/to/photo.jpg") == (".jpg",)


class TestFinalExtension:
    """Tests for _get_final_extension helper."""

    def test_simple_extension(self):
        assert _get_final_extension("photo.jpg") == ".jpg"

    def test_double_extension_returns_final(self):
        assert _get_final_extension("invoice.pdf.exe") == ".exe"

    def test_uppercase(self):
        assert _get_final_extension("document.EXE") == ".exe"

    def test_no_extension(self):
        assert _get_final_extension("README") == ""


class TestExtensionMismatch:
    """Tests for _check_extension_mismatch helper (Phase 2J critical test)."""

    def test_pdf_exe_is_mismatch(self):
        """invoice.pdf.exe must NOT be treated as PDF."""
        assert _check_extension_mismatch((".pdf", ".exe")) is True

    def test_doc_scr_is_mismatch(self):
        assert _check_extension_mismatch((".doc", ".scr")) is True

    def test_jpg_vbs_is_mismatch(self):
        assert _check_extension_mismatch((".jpg", ".vbs")) is True

    def test_txt_docm_is_mismatch(self):
        assert _check_extension_mismatch((".txt", ".docm")) is True

    def test_exe_alone_is_not_mismatch(self):
        assert _check_extension_mismatch((".exe",)) is False

    def test_pdf_alone_is_not_mismatch(self):
        assert _check_extension_mismatch((".pdf",)) is False

    def test_zip_exe_not_mismatch_no_benign(self):
        """zip is archive, not benign document — not a deception pattern."""
        assert _check_extension_mismatch((".zip", ".exe")) is False

    def test_empty_is_not_mismatch(self):
        assert _check_extension_mismatch(()) is False


class TestSuspiciousFilename:
    """Tests for _check_suspicious_filename helper."""

    def test_invoice_payment(self):
        assert _check_suspicious_filename("invoice_payment.exe") is True

    def test_password_reset(self):
        assert _check_suspicious_filename("password_reset.scr") is True

    def test_account_verify(self):
        assert _check_suspicious_filename("account_verify.bat") is True

    def test_normal_filename(self):
        assert _check_suspicious_filename("vacation_photo.jpg") is False

    def test_report_filename(self):
        assert _check_suspicious_filename("quarterly_report.pdf") is False

    def test_case_insensitive(self):
        assert _check_suspicious_filename("INVOICE_PAYMENT.exe") is True

    def test_urgent_notice(self):
        assert _check_suspicious_filename("urgent_notice.pdf") is True

    def test_delivery_confirm(self):
        assert _check_suspicious_filename("delivery_confirm.pdf") is True


class TestFeatureExtraction:
    """Tests for the full extract_file_features pipeline."""

    def test_safe_jpg(self):
        inp = FileAnalysisInput(filename="photo.jpg")
        f = extract_file_features(inp)
        assert f.final_extension == ".jpg"
        assert f.extension_count == 1
        assert f.has_double_extension is False
        assert f.has_dangerous_extension is False
        assert f.has_script_extension is False

    def test_dangerous_exe(self):
        inp = FileAnalysisInput(filename="setup.exe")
        f = extract_file_features(inp)
        assert f.final_extension == ".exe"
        assert f.has_dangerous_extension is True
        assert f.has_double_extension is False
        assert f.has_extension_mismatch is False

    def test_deceptive_double_extension(self):
        inp = FileAnalysisInput(filename="invoice.pdf.exe")
        f = extract_file_features(inp)
        assert f.has_double_extension is True
        assert f.has_dangerous_extension is True
        assert f.has_extension_mismatch is True
        assert f.all_extensions == (".pdf", ".exe")

    def test_triple_extension(self):
        inp = FileAnalysisInput(filename="report.pdf.zip.exe")
        f = extract_file_features(inp)
        assert f.has_double_extension is True
        assert f.has_multiple_extensions is True
        assert f.extension_count == 3

    def test_script_extension(self):
        inp = FileAnalysisInput(filename="helper.vbs")
        f = extract_file_features(inp)
        assert f.has_script_extension is True
        assert f.has_dangerous_extension is False

    def test_archive_extension(self):
        inp = FileAnalysisInput(filename="backup.zip")
        f = extract_file_features(inp)
        assert f.has_archive_extension is True
        assert f.has_dangerous_extension is False

    def test_macro_document(self):
        inp = FileAnalysisInput(filename="report.docm")
        f = extract_file_features(inp)
        assert f.has_document_macro_extension is True

    def test_excessive_filename_length(self):
        long_name = "a" * 201 + ".pdf"
        inp = FileAnalysisInput(filename=long_name)
        f = extract_file_features(inp)
        assert f.has_excessive_length is True

    def test_normal_filename_length(self):
        inp = FileAnalysisInput(filename="resume.docx")
        f = extract_file_features(inp)
        assert f.has_excessive_length is False

    def test_whitespace_stripping(self):
        inp = FileAnalysisInput(filename="  invoice.pdf.exe  ")
        f = extract_file_features(inp)
        assert f.filename == "invoice.pdf.exe"
        assert f.has_extension_mismatch is True

    def test_no_extension(self):
        inp = FileAnalysisInput(filename="README")
        f = extract_file_features(inp)
        assert f.extension_count == 0
        assert f.final_extension == ""
        assert f.has_dangerous_extension is False


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2C — Detection Rules Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectionRules:
    """Tests for rule evaluation."""

    def _get_triggered_rules(self, filename: str) -> set[str]:
        inp = FileAnalysisInput(filename=filename)
        features = extract_file_features(inp)
        results = evaluate_file_rules(features)
        return {r.rule_id for r in results if r.triggered}

    def test_deceptive_extension_triggers_mismatch(self):
        rules = self._get_triggered_rules("invoice.pdf.exe")
        assert "EXTENSION_MISMATCH_DECEPTION" in rules

    def test_deceptive_extension_does_not_double_count(self):
        """EXTENSION_MISMATCH_DECEPTION should suppress DANGEROUS_FILE_EXTENSION."""
        rules = self._get_triggered_rules("invoice.pdf.exe")
        assert "EXTENSION_MISMATCH_DECEPTION" in rules
        assert "DANGEROUS_FILE_EXTENSION" not in rules

    def test_dangerous_extension_alone(self):
        rules = self._get_triggered_rules("setup.exe")
        assert "DANGEROUS_FILE_EXTENSION" in rules
        assert "EXTENSION_MISMATCH_DECEPTION" not in rules

    def test_script_extension(self):
        rules = self._get_triggered_rules("helper.vbs")
        assert "SCRIPT_FILE_EXTENSION" in rules

    def test_double_extension_without_deception(self):
        """photo.jpg.pdf has double extension but both are benign."""
        rules = self._get_triggered_rules("photo.jpg.pdf")
        # Both are benign, final is not dangerous → no mismatch
        assert "EXTENSION_MISMATCH_DECEPTION" not in rules
        # Has double extension but not dangerous → DOUBLE_EXTENSION triggers
        assert "DOUBLE_EXTENSION" in rules

    def test_macro_document(self):
        rules = self._get_triggered_rules("report.docm")
        assert "DOCUMENT_MACRO_EXTENSION" in rules

    def test_suspicious_social_engineering_dangerous(self):
        rules = self._get_triggered_rules("invoice_payment.exe")
        assert "DANGEROUS_SOCIAL_ENGINEERING_FILENAME" in rules

    def test_suspicious_filename_benign_extension(self):
        rules = self._get_triggered_rules("invoice_payment.pdf")
        assert "SUSPICIOUS_FILENAME_PATTERN" in rules
        assert "DANGEROUS_SOCIAL_ENGINEERING_FILENAME" not in rules

    def test_archive_with_suspicious_name(self):
        rules = self._get_triggered_rules("invoice_payment.zip")
        assert "SUSPICIOUS_ARCHIVE_NAME" in rules

    def test_excessive_length(self):
        long_name = "a" * 201 + ".pdf"
        rules = self._get_triggered_rules(long_name)
        assert "EXCESSIVE_FILENAME_LENGTH" in rules

    def test_safe_file_triggers_nothing(self):
        rules = self._get_triggered_rules("photo.jpg")
        assert len(rules) == 0

    def test_safe_pdf_triggers_nothing(self):
        rules = self._get_triggered_rules("document.pdf")
        assert len(rules) == 0

    def test_safe_docx_triggers_nothing(self):
        rules = self._get_triggered_rules("resume.docx")
        assert len(rules) == 0

    def test_plain_zip_triggers_nothing(self):
        """backup.zip should NOT be dangerous by itself."""
        rules = self._get_triggered_rules("backup.zip")
        assert len(rules) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2D / 2E — Scoring and Classification Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestClassification:
    """Tests for classify_file_risk_score."""

    def test_zero_is_safe(self):
        assert classify_file_risk_score(0) == "SAFE"

    def test_25_is_safe(self):
        assert classify_file_risk_score(25) == "SAFE"

    def test_26_is_suspicious(self):
        assert classify_file_risk_score(26) == "SUSPICIOUS"

    def test_65_is_suspicious(self):
        assert classify_file_risk_score(65) == "SUSPICIOUS"

    def test_66_is_dangerous(self):
        assert classify_file_risk_score(66) == "DANGEROUS"

    def test_100_is_dangerous(self):
        assert classify_file_risk_score(100) == "DANGEROUS"


class TestScoringPipeline:
    """End-to-end scoring tests."""

    def test_safe_jpg(self):
        result = analyze_file("photo.jpg")
        assert result.status == "SAFE"
        assert result.risk_score == 0
        assert len(result.reasons) == 0

    def test_safe_pdf(self):
        result = analyze_file("document.pdf")
        assert result.status == "SAFE"

    def test_safe_docx(self):
        result = analyze_file("resume.docx")
        assert result.status == "SAFE"

    def test_dangerous_exe(self):
        result = analyze_file("setup.exe")
        assert result.status in ("SUSPICIOUS", "DANGEROUS")
        assert result.risk_score > 25

    def test_dangerous_deceptive_extension(self):
        result = analyze_file("invoice.pdf.exe")
        assert result.status == "DANGEROUS"
        assert result.risk_score >= 50

    def test_dangerous_script(self):
        result = analyze_file("script.vbs")
        assert result.status in ("SUSPICIOUS", "DANGEROUS")
        assert result.risk_score >= 26

    def test_dangerous_powershell(self):
        result = analyze_file("powershell.ps1")
        assert result.status in ("SUSPICIOUS", "DANGEROUS")
        assert result.risk_score >= 26

    def test_dangerous_screensaver(self):
        result = analyze_file("setup.scr")
        assert result.status in ("SUSPICIOUS", "DANGEROUS")

    def test_suspicious_archive_phishing(self):
        result = analyze_file("invoice_payment.zip")
        assert result.risk_score >= 10

    def test_suspicious_long_filename(self):
        long_name = "a" * 201 + ".pdf"
        result = analyze_file(long_name)
        assert result.risk_score >= 10

    def test_suspicious_double_extension_benign(self):
        result = analyze_file("photo.jpg.pdf")
        assert result.risk_score > 0  # double extension triggers

    def test_dangerous_macro_document(self):
        result = analyze_file("document.docm")
        assert result.risk_score >= 25

    def test_score_clamped_to_100(self):
        """Even with many triggers, score should not exceed 100."""
        result = analyze_file("invoice_payment.pdf.exe")
        assert result.risk_score <= 100

    def test_score_clamped_to_0(self):
        result = analyze_file("photo.jpg")
        assert result.risk_score >= 0

    def test_result_has_asset_type(self):
        result = analyze_file("photo.jpg")
        assert result.asset_type == "file"

    def test_result_has_filename(self):
        result = analyze_file("invoice.pdf.exe")
        assert result.filename == "invoice.pdf.exe"

    def test_plain_zip_is_safe(self):
        """backup.zip must not be treated as dangerous."""
        result = analyze_file("backup.zip")
        assert result.status == "SAFE"
        assert result.risk_score == 0


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2J — Security Edge Case Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestCaseInsensitivity:
    """Extension parser must be case-insensitive (Phase 2J requirement)."""

    def test_pdf_exe_uppercase(self):
        result = analyze_file("invoice.PDF.EXE")
        assert result.status == "DANGEROUS"

    def test_pdf_exe_mixed_case(self):
        result = analyze_file("invoice.pdf.ExE")
        assert result.status == "DANGEROUS"

    def test_pdf_uppercase_exe_lowercase(self):
        result = analyze_file("invoice.PDF.exe")
        assert result.status == "DANGEROUS"

    def test_all_caps(self):
        result = analyze_file("SETUP.EXE")
        assert result.risk_score > 25

    def test_mixed_case_vbs(self):
        result = analyze_file("helper.VBS")
        assert result.risk_score >= 26


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_filename(self):
        result = analyze_file("")
        assert result.status == "SAFE"
        assert result.risk_score == 0

    def test_filename_only_dots(self):
        result = analyze_file("...")
        assert isinstance(result.risk_score, int)

    def test_filename_no_extension(self):
        result = analyze_file("README")
        assert result.status == "SAFE"

    def test_filename_with_spaces(self):
        result = analyze_file("my document.pdf")
        assert result.status == "SAFE"

    def test_filename_leading_trailing_spaces(self):
        result = analyze_file("  invoice.pdf.exe  ")
        assert result.status == "DANGEROUS"

    def test_unicode_filename(self):
        result = analyze_file("文件.pdf")
        assert result.status == "SAFE"

    def test_unicode_filename_with_exe(self):
        result = analyze_file("文件.pdf.exe")
        assert result.status == "DANGEROUS"

    def test_very_long_filename_with_exe(self):
        long_name = "a" * 250 + ".exe"
        result = analyze_file(long_name)
        assert result.risk_score > 25

    def test_unknown_extension(self):
        result = analyze_file("file.xyz123")
        assert result.status == "SAFE"

    def test_multiple_dots_no_real_extensions(self):
        result = analyze_file("v1.2.3.4.txt")
        assert isinstance(result.risk_score, int)


class TestDeceptionPreventionCritical:
    """Critical tests: ensure the final extension determines the true type.

    Phase 2J requirement: "filename.pdf.exe" must NOT be treated as PDF.
    """

    def test_pdf_exe_not_pdf(self):
        inp = FileAnalysisInput(filename="filename.pdf.exe")
        features = extract_file_features(inp)
        assert features.final_extension == ".exe"
        assert features.has_dangerous_extension is True

    def test_doc_scr_not_doc(self):
        inp = FileAnalysisInput(filename="report.doc.scr")
        features = extract_file_features(inp)
        assert features.final_extension == ".scr"
        assert features.has_dangerous_extension is True

    def test_jpg_bat_not_jpg(self):
        inp = FileAnalysisInput(filename="image.jpg.bat")
        features = extract_file_features(inp)
        assert features.final_extension == ".bat"
        assert features.has_dangerous_extension is True

    def test_xlsx_cmd_not_xlsx(self):
        inp = FileAnalysisInput(filename="spreadsheet.xlsx.cmd")
        features = extract_file_features(inp)
        assert features.final_extension == ".cmd"
        assert features.has_dangerous_extension is True


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2K — Regression: existing URL detection unaffected
# ═══════════════════════════════════════════════════════════════════════════


class TestURLDetectionRegression:
    """Verify that existing URL detection is completely unaffected."""

    def test_url_scorer_still_works(self):
        from backend.detection.engine.scorer import analyze_url_security
        result = analyze_url_security("https://safe-example.com")
        assert result.status == "SAFE"

    def test_url_rules_still_work(self):
        from backend.detection.engine.scorer import analyze_url_security
        result = analyze_url_security("http://192.168.1.1/phishing")
        assert result.risk_score > 0

    def test_url_imports_not_modified(self):
        """Ensure URL detection modules can be imported independently."""
        from backend.detection.engine.scorer import DetectionResult, classify_risk_score
        from backend.detection.rules.rules import evaluate_rules, RULES
        from backend.detection.features.extractor import extract_features
        assert len(RULES) > 0

    def test_file_module_isolated_from_url(self):
        """File detection module does not reference URL modules."""
        import inspect
        from backend.detection.file_detection import scorer as file_scorer
        source = inspect.getsource(file_scorer)
        assert "analyze_url" not in source
        assert "URLFeatures" not in source
