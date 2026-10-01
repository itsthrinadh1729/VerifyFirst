"""File detection service for VerifyFirst.

Provides the top-level API for file analysis, producing results compatible
with the existing SecurityEvent model used by the Security Center.
"""

from backend.detection.file_detection.schemas import (
    FileAnalysisInput,
    FileDetectionResult,
)
from backend.detection.file_detection.scorer import analyze_file_security


def analyze_file(
    filename: str,
    *,
    mime_type: str = "",
    file_size: int = 0,
    source: str = "whatsapp",
) -> FileDetectionResult:
    """Analyze a file by its metadata and return a detection result.

    This is the primary entry point for file detection. It accepts
    raw file metadata, constructs the pipeline input, and returns
    a result compatible with the SecurityEvent model.

    Args:
        filename: The original filename (e.g., "invoice.pdf.exe").
        mime_type: Optional MIME type if available.
        file_size: Optional file size in bytes.
        source: Source of the file (default: "whatsapp").

    Returns:
        FileDetectionResult with status, risk_score, and detection reasons.
    """
    # Derive the extension from the filename
    extension = ""
    if "." in filename:
        extension = filename.rsplit(".", 1)[-1].lower()

    input_data = FileAnalysisInput(
        filename=filename,
        extension=extension,
        mime_type=mime_type,
        file_size=file_size,
        source=source,
    )

    return analyze_file_security(input_data)
