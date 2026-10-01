"""File feature extraction for VerifyFirst.

Extracts deterministic features from file metadata (filename, extension, size)
without inspecting file contents. This is the first stage of the file detection
pipeline.
"""

import os
import re

from backend.detection.file_detection.schemas import FileAnalysisInput, FileFeatures


# ── Extension sets ──────────────────────────────────────────────────────────

DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd",
    ".ps1", ".psm1", ".psd1",
    ".msi", ".msp", ".mst",
    ".cpl", ".inf", ".reg",
    ".dll", ".sys", ".drv",
    ".application", ".appref-ms",
    ".gadget", ".ws", ".wsf", ".wsc", ".wsh",
})

SCRIPT_EXTENSIONS: frozenset[str] = frozenset({
    ".js", ".jse", ".vbs", ".vbe", ".hta",
    ".py", ".pyw", ".rb", ".pl", ".sh",
    ".bash", ".csh", ".ksh", ".zsh",
    ".php", ".jsp", ".asp", ".aspx",
    ".swf",
})

ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".bz2", ".xz", ".cab", ".iso", ".img",
    ".dmg", ".lzh", ".arj", ".ace",
})

DOCUMENT_MACRO_EXTENSIONS: frozenset[str] = frozenset({
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
    ".sldm", ".xlam", ".ppam",
})

# Extensions that are commonly innocent document types (used to detect
# deceptive double-extension patterns like "invoice.pdf.exe")
BENIGN_DOCUMENT_EXTENSIONS: frozenset[str] = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".rtf", ".odt", ".ods", ".odp",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav",
    ".csv", ".xml", ".json", ".html", ".htm",
})

# Filename patterns commonly used in social engineering attacks
SUSPICIOUS_FILENAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"invoice[_\-\s]*(payment|receipt|confirm)?", re.IGNORECASE),
    re.compile(r"password[_\-\s]*(reset|change|update|confirm)", re.IGNORECASE),
    re.compile(r"account[_\-\s]*(verify|suspend|locked|confirm|alert|verification)", re.IGNORECASE),
    re.compile(r"(urgent|important)[_\-\s]*(notice|document|update|action|invoice)", re.IGNORECASE),
    re.compile(r"bank[_\-\s]*(statement|transfer|confirm|alert|security)", re.IGNORECASE),
    re.compile(r"(tax|refund)[_\-\s]*(return|document|receipt|form)", re.IGNORECASE),
    re.compile(r"payment[_\-\s]*(required)", re.IGNORECASE),
    re.compile(r"(delivery|shipment|package|tracking)[_\-\s]*(confirm|notice|update|fail)", re.IGNORECASE),
    re.compile(r"(prize|reward|winner|lottery|bonus)[_\-\s]*(claim|confirm|notice)", re.IGNORECASE),
    re.compile(r"(security|virus|malware|threat)[_\-\s]*(scan|alert|warning|update|remove)", re.IGNORECASE),
    re.compile(r"(payment|wire|transfer)[_\-\s]*(receipt|confirm|detail|instruction)", re.IGNORECASE),
]

# Maximum reasonable filename length before it becomes suspicious
MAX_REASONABLE_FILENAME_LENGTH: int = 200


def _extract_all_extensions(filename: str) -> tuple[str, ...]:
    """Extract all extensions from a filename, in order.

    Example:
        "invoice.pdf.exe" → (".pdf", ".exe")
        "photo.jpg"       → (".jpg",)
        "README"          → ()
    """
    basename = os.path.basename(filename)
    parts = basename.split(".")

    if len(parts) <= 1:
        return ()

    # The first part is the stem, remaining parts are extensions
    return tuple(f".{ext.lower()}" for ext in parts[1:] if ext)


def _get_final_extension(filename: str) -> str:
    """Get the final (true) extension of a filename, lowercased.

    Example:
        "invoice.pdf.exe" → ".exe"
        "photo.jpg"       → ".jpg"
        "README"          → ""
    """
    _, ext = os.path.splitext(filename)
    return ext.lower()


def _check_extension_mismatch(all_extensions: tuple[str, ...]) -> bool:
    """Check if a filename has a deceptive extension combination.

    Returns True when a benign document extension precedes a dangerous
    or script extension — the classic social engineering pattern.

    Example: ("invoice.pdf.exe") → benign ".pdf" followed by dangerous ".exe"
    """
    if len(all_extensions) < 2:
        return False

    final_ext = all_extensions[-1]
    is_final_dangerous = (
        final_ext in DANGEROUS_EXTENSIONS
        or final_ext in SCRIPT_EXTENSIONS
        or final_ext in DOCUMENT_MACRO_EXTENSIONS
    )

    if not is_final_dangerous:
        return False

    # Check if any preceding extension is a benign document type
    preceding = all_extensions[:-1]
    return any(ext in BENIGN_DOCUMENT_EXTENSIONS for ext in preceding)


def _check_suspicious_filename(filename: str) -> bool:
    """Check if the filename matches known social engineering patterns."""
    stem = os.path.splitext(os.path.basename(filename))[0]
    return any(pattern.search(stem) for pattern in SUSPICIOUS_FILENAME_PATTERNS)


def extract_file_features(input_data: FileAnalysisInput) -> FileFeatures:
    """Extract deterministic features from file metadata.

    This is a pure function: same input always produces the same output.
    No file content is inspected.
    """
    filename = input_data.filename.strip()
    filename_lower = filename.lower()

    all_extensions = _extract_all_extensions(filename)
    final_extension = _get_final_extension(filename)
    extension_count = len(all_extensions)

    has_double_extension = extension_count >= 2
    has_multiple_extensions = extension_count >= 3

    has_dangerous_extension = final_extension in DANGEROUS_EXTENSIONS
    has_script_extension = final_extension in SCRIPT_EXTENSIONS
    has_archive_extension = final_extension in ARCHIVE_EXTENSIONS
    has_document_macro_extension = final_extension in DOCUMENT_MACRO_EXTENSIONS

    has_extension_mismatch = _check_extension_mismatch(all_extensions)
    has_suspicious_filename_pattern = _check_suspicious_filename(filename)
    has_excessive_length = len(filename) > MAX_REASONABLE_FILENAME_LENGTH

    return FileFeatures(
        filename=filename,
        filename_lower=filename_lower,
        filename_length=len(filename),
        final_extension=final_extension,
        extension_count=extension_count,
        all_extensions=all_extensions,
        has_double_extension=has_double_extension,
        has_multiple_extensions=has_multiple_extensions,
        has_dangerous_extension=has_dangerous_extension,
        has_script_extension=has_script_extension,
        has_archive_extension=has_archive_extension,
        has_document_macro_extension=has_document_macro_extension,
        has_extension_mismatch=has_extension_mismatch,
        has_suspicious_filename_pattern=has_suspicious_filename_pattern,
        has_excessive_length=has_excessive_length,
        mime_type=input_data.mime_type,
        file_size=input_data.file_size,
        source=input_data.source,
    )
