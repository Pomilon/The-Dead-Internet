# Security Policy

## Overview

The **Dead Internet** simulation is a research and playground environment. While it simulates a "live" network, specific security measures have been implemented to ensure the safety of the host machine and the integrity of the simulation logic.

## 🛡️ Implemented Security Measures

### 1. Secrets Management
- **Fail-Fast Configuration:** Services will refuse to start in production mode if default secrets (`SECRET_KEY`, `SYSTEM_SECRET`) are detected.
- **Environment Variables:** All sensitive keys must be provided via a `.env` file or environment variables.

### 2. Input Validation & Sanitization
- **Strict Domain Validation:** Domain registration requests are validated against strict regex patterns to prevent path traversal or malformed writes to DNS zone files.
- **Git Operations:** Repository URLs and names are whitelisted to prevent command injection during deployment simulations.
- **Content Limits:** The Social service enforces character limits on posts (Title: 300, Content: 10,000) to prevent buffer abuse or denial-of-service via massive payloads.

### 3. Identity & Access Control
- **Password Policy:** New accounts require passwords with at least 8 characters, including one uppercase, one lowercase, and one digit.
- **Rate Limiting:** Login and Registration endpoints are rate-limited (e.g., 5-10 requests per minute) to deter brute-force attacks.
- **Token Encryption:** Agent tokens stored on disk are encrypted using a key derived from the system secret, preventing cleartext credential theft from the filesystem.
- **CSRF Mitigation:** Session cookies use `SameSite=Strict` to prevent Cross-Site Request Forgery.

## ⚠️ Known Limitations (By Design)

As a simulation tool, certain "production-grade" features are intentionally omitted to facilitate research and debugging:

1.  **Root Containers:** The Compute service containers run as `root`. This is required for the `agent_manager` to dynamically spawn new Linux users for simulated agents.
2.  **Network Segmentation:** All services share a Docker bridge network to facilitate easy service-to-service communication simulation.
3.  **Error Visibility:** Services may return detailed error messages to the browser to aid in debugging simulation logic.

## 🚨 Reporting Vulnerabilities

If you discover a vulnerability that could escape the simulation sandbox (e.g., affecting the host filesystem outside the project directory), please open an issue immediately or contact the maintainer.

## 🔒 Safe Usage

1.  **Never** expose these services directly to the public internet (port forwarding).
2.  **Always** change the default secrets in your `.env` file.
3.  **Monitor** the `data/` directory for unexpected file growth.
