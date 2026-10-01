"""File detection schemas for VerifyFirst.

Defines the data structures used throughout the file detection pipeline.
These are intentionally separate from URL detection schemas.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FileAnalysisInput:
    """Input metadata for file analysis.

    Represents the minimum metadata needed to assess a file's risk
    without accessing the file's actual contents.
    """

    filename: str
    extension: str = ""
    mime_type: str = ""
    file_size: int = 0
    source: str = "whatsapp"


@dataclass(frozen=True)
class FileFeatures:
    """Extracted features from file metadata.

    All features are deterministic and derived solely from the filename
    and associated metadata — no file content inspection is performed.
    """

    # Core filename properties
    filename: str = ""
    filename_lower: str = ""
    filename_length: int = 0

    # Extension analysis
    final_extension: str = ""
    extension_count: int = 0
    all_extensions: tuple[str, ...] = ()

    # Boolean indicators
    has_double_extension: bool = False
    has_multiple_extensions: bool = False
    has_dangerous_extension: bool = False
    has_script_extension: bool = False
    has_archive_extension: bool = False
    has_document_macro_extension: bool = False

    # Filename deception
    has_extension_mismatch: bool = False
    has_suspicious_filename_pattern: bool = False
    has_excessive_length: bool = False

    # Metadata
    mime_type: str = ""
    file_size: int = 0
    source: str = ""


@dataclass(frozen=True)
class FileDetectionReason:
    """Structured detection reason for a file rule trigger."""

    rule: str
    message: str


@dataclass(frozen=True)
class FileDetectionResult:
    """Final detection result for a file.

    Mirrors the structure of DetectionResult from the URL engine
    so both can produce compatible SecurityEvents.
    """

    status: str  # SAFE, SUSPICIOUS, DANGEROUS
    risk_score: int
    reasons: list[FileDetectionReason] = field(default_factory=list)
    filename: str = ""
    asset_type: str = "file"
