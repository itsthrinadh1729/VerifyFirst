# VerifyFirst Privacy Policy

This policy explains how VerifyFirst handles data to provide link and message security analysis.

## 1. Data We Access
VerifyFirst accesses content from active web pages only when specific threat-detection workflows are invoked:

### URL Protection
- **Candidate URLs:** Discovered via regular expressions within web content.

### Message Analysis
- **Message Content:** For WhatsApp Web, incoming message text is accessed strictly for threat analysis when the message-analysis functionality is invoked. Contact names, sender phone numbers, and chat titles are explicitly excluded and not accessed.
- **File Metadata:** Only the **filename** of document attachments is accessed. MIME type and file size are **not** accessed.

## 2. Data We Transmit
When analyzing content for security risks, VerifyFirst transmits specific data to our backend API via HTTPS:

### URL Protection
- **Candidate URLs:** The raw candidate string is transmitted to the backend for heuristic security analysis.

### Message Analysis
- **Message Content:** The normalized message string is transmitted to the message detection API for threat analysis.
- **File Metadata:** Only the **filename** is transmitted.

### Session Isolation
- **Chat Identifier:** An ephemeral `chatId` is sent to the backend. This is used strictly for isolating, correlating, and deduplicating alerts within your current browser session.

## 3. Third-Party Services
The VerifyFirst backend may query external services (such as Google Safe Browsing) to enhance threat intelligence for URL Protection. This occurs strictly server-side; the Chrome extension does not communicate directly with these third-party providers.

## 4. Data Storage and Retention
- **Browser-local data:** VerifyFirst stores your scan history and settings locally on your device using Chrome's extension storage APIs.
- **Backend processing:** The VerifyFirst backend processes submitted URLs, message content, and metadata for security analysis. 
- **Infrastructure Logging:** The production backend infrastructure is configured with strict logging rules. Operational logs only retain metadata (e.g., timestamp, request path, status code, latency). The infrastructure **does not log or retain** request bodies containing URLs, message content, or chat identifiers.

## 5. User Controls
- **Wipe History**: You can delete your recorded security events at any time using the "Wipe History" button in the Security Center, which securely removes the specific history records from local storage.
- **Export Data**: You can export your scan history in **JSON** format.
- **Uninstall**: Removing the extension removes the extension's locally stored data according to Chrome's extension storage behavior.

## 6. Chrome Permissions
VerifyFirst requires permissions strictly necessary for its security functions. All permissions are documented and limited to active scanning and local storage management.
