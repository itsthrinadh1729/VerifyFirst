"""File detection rules for VerifyFirst.

Deterministic rules that evaluate extracted file features and produce
structured evidence. Each rule has an independent weight calibrated for
file-specific risk (not reused from URL weights).
"""

from dataclasses import dataclass
from typing import Callable

from backend.detection.file_detection.schemas import FileFeatures


@dataclass(frozen=True)
class FileRuleResult:
    """Outcome of evaluating a single file detection rule."""

    rule_id: str
    triggered: bool
    weight: int
    message: str


@dataclass(frozen=True)
class FileRuleDefinition:
    """Definition of a file detection rule."""

    rule_id: str
    weight: int
    message: str
    evaluator: Callable[[FileFeatures], bool]

    def evaluate(self, features: FileFeatures) -> FileRuleResult:
        triggered = bool(self.evaluator(features))
        return FileRuleResult(
            rule_id=self.rule_id,
            triggered=triggered,
            weight=self.weight if triggered else 0,
            message=self.message if triggered else "",
        )


# ── File Detection Rules ────────────────────────────────────────────────────
#
# Weight calibration for files (independent of URL weights):
#
#   Critical (40-50): Almost certainly malicious
#     - Extension mismatch deception (document.pdf.exe)
#     - Dangerous executable with social engineering name
#
#   High (25-35): Strong malicious indicator
#     - Dangerous executable extension alone
#     - Script file extension
#     - Macro-enabled document
#
#   Medium (15-20): Suspicious indicator, needs combination
#     - Double extension without deception
#     - Suspicious filename pattern alone
#     - Multiple extensions
#
#   Low (5-10): Mild indicator
#     - Excessive filename length
#     - Archive with suspicious naming
#

FILE_RULES: list[FileRuleDefinition] = [
    # ── P0: Critical threats ──

    FileRuleDefinition(
        rule_id="EXTENSION_MISMATCH_DECEPTION",
        weight=70,
        message=(
            "The filename disguises a dangerous file type behind "
            "an innocent-looking extension (e.g., document.pdf.exe)."
        ),
        evaluator=lambda f: f.has_extension_mismatch,
    ),

    FileRuleDefinition(
        rule_id="DANGEROUS_FILE_EXTENSION",
        weight=35,
        message=(
            "The file has an executable extension commonly associated "
            "with malware distribution."
        ),
        evaluator=lambda f: f.has_dangerous_extension and not f.has_extension_mismatch,
    ),

    FileRuleDefinition(
        rule_id="SCRIPT_FILE_EXTENSION",
        weight=30,
        message=(
            "The file has a script extension that can execute "
            "commands on your device."
        ),
        evaluator=lambda f: f.has_script_extension,
    ),

    # ── P0: Filename deception ──

    FileRuleDefinition(
        rule_id="DANGEROUS_SOCIAL_ENGINEERING_FILENAME",
        weight=15,
        message=(
            "The filename uses wording commonly associated with "
            "phishing or social engineering attacks."
        ),
        evaluator=lambda f: (
            f.has_suspicious_filename_pattern
            and (f.has_dangerous_extension or f.has_script_extension)
        ),
    ),

    # ── P1: Suspicious indicators ──

    FileRuleDefinition(
        rule_id="DOUBLE_EXTENSION",
        weight=20,
        message=(
            "The filename contains multiple extensions, which "
            "may be used to disguise the true file type."
        ),
        evaluator=lambda f: (
            f.has_double_extension
            and not f.has_extension_mismatch
            and not f.has_archive_extension
        ),
    ),

    FileRuleDefinition(
        rule_id="MULTIPLE_EXTENSIONS",
        weight=10,
        message=(
            "The filename contains three or more extensions, "
            "which is highly unusual."
        ),
        evaluator=lambda f: f.has_multiple_extensions and not f.has_extension_mismatch,
    ),

    FileRuleDefinition(
        rule_id="DOCUMENT_MACRO_EXTENSION",
        weight=25,
        message=(
            "The file is a macro-enabled document that can "
            "execute code when opened."
        ),
        evaluator=lambda f: f.has_document_macro_extension,
    ),

    # ── P1: Suspicious indicators (lower severity) ──

    FileRuleDefinition(
        rule_id="SUSPICIOUS_FILENAME_PATTERN",
        weight=10,
        message=(
            "The filename matches patterns commonly used in "
            "phishing or social engineering."
        ),
        evaluator=lambda f: (
            f.has_suspicious_filename_pattern
            and not f.has_dangerous_extension
            and not f.has_script_extension
        ),
    ),

    FileRuleDefinition(
        rule_id="EXCESSIVE_FILENAME_LENGTH",
        weight=10,
        message=(
            "The filename is unusually long, which may be used "
            "to hide the true file extension."
        ),
        evaluator=lambda f: f.has_excessive_length,
    ),

    FileRuleDefinition(
        rule_id="SUSPICIOUS_ARCHIVE_NAME",
        weight=10,
        message=(
            "An archive file has a filename pattern commonly "
            "associated with phishing campaigns."
        ),
        evaluator=lambda f: (
            f.has_archive_extension
            and f.has_suspicious_filename_pattern
        ),
    ),
]


def evaluate_file_rules(features: FileFeatures) -> list[FileRuleResult]:
    """Evaluate all file detection rules against extracted file features."""
    return [rule.evaluate(features) for rule in FILE_RULES]
