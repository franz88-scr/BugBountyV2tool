"""Automated remediation guidance — CWE-to-fix mappings for all vulnerability types.

Provides actionable fix recommendations for every finding type in the pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class Remediation:
    """Remediation guidance for a single vulnerability type.

    Attributes:
        cwe: CWE identifier (e.g. ``"CWE-79"``).
        title: Human-readable vulnerability title.
        severity: Expected severity (``"critical"``, ``"high"``, ``"medium"``, ``"low"``).
        description: What the vulnerability is and why it matters.
        remediation: Numbered remediation steps (newline-separated).
        references: List of reference URLs (OWASP, CWE, etc.).
    """
    cwe: str
    title: str
    severity: str
    description: str
    remediation: str
    references: list


REMEDIATIONS: Dict[str, Remediation] = {
    "xss": Remediation(
        cwe="CWE-79", title="Cross-Site Scripting (XSS)", severity="high",
        description="Untrusted user input is reflected or stored in web pages without proper sanitization, allowing attackers to execute arbitrary JavaScript in victims' browsers.",
        remediation=(
            "1. Encode all output using context-appropriate encoding (HTML entity, JavaScript, URL, CSS)\n"
            "2. Use Content-Security-Policy (CSP) headers to restrict script execution\n"
            "3. Validate and sanitize all user input on the server side\n"
            "4. Use frameworks that auto-escape by default (React, Angular, Jinja2 autoescape)\n"
            "5. For DOM XSS: avoid dangerous sinks like innerHTML, document.write, eval"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html"],
    ),
    "sqli": Remediation(
        cwe="CWE-89", title="SQL Injection", severity="critical",
        description="User input is concatenated into SQL queries without parameterization, allowing attackers to manipulate database queries.",
        remediation=(
            "1. Use parameterized queries (prepared statements) for ALL database interactions\n"
            "2. Never concatenate user input into SQL strings\n"
            "3. Use ORM frameworks where possible\n"
            "4. Apply least-privilege database user accounts\n"
            "5. Enable WAF rules for SQL injection patterns as defense-in-depth"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    ),
    "ssrf": Remediation(
        cwe="CWE-918", title="Server-Side Request Forgery (SSRF)", severity="high",
        description="Application fetches attacker-controlled URLs, potentially reaching internal services, cloud metadata endpoints, or other restricted resources.",
        remediation=(
            "1. Validate and whitelist allowed target URLs/domains\n"
            "2. Block requests to private/internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 169.254.169.254)\n"
            "3. Use a dedicated outbound proxy/gateway for URL fetching\n"
            "4. Disable unnecessary URL schemes (file://, gopher://, dict://)\n"
            "5. Use network segmentation to isolate sensitive services"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
    ),
    "lfi": Remediation(
        cwe="CWE-98", title="Local File Inclusion (LFI)", severity="high",
        description="User input controls file path parameters, allowing attackers to read arbitrary files from the server filesystem.",
        remediation=(
            "1. Never use user input directly in file path operations\n"
            "2. Validate and whitelist allowed file names/paths\n"
            "3. Remove path traversal sequences (../) and null bytes\n"
            "4. Use chroot or container isolation to limit filesystem access\n"
            "5. Set restrictive file permissions on sensitive files"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/File_Inclusion_Prevention_Cheat_Sheet.html"],
    ),
    "rce": Remediation(
        cwe="CWE-78", title="Remote Code Execution (RCE)", severity="critical",
        description="User input reaches OS command execution, shell invocations, or dangerous function calls, allowing full system compromise.",
        remediation=(
            "1. NEVER pass user input to system commands (os.system, subprocess with shell=True)\n"
            "2. Use safe APIs instead of shell commands (e.g., os.path.join instead of shell expansion)\n"
            "3. Apply strict input validation with allowlists\n"
            "4. Use language-level sandboxing if dynamic code execution is required\n"
            "5. Run applications with minimal OS privileges (non-root, dedicated user)"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
    ),
    "ssti": Remediation(
        cwe="CWE-1336", title="Server-Side Template Injection (SSTI)", severity="high",
        description="User input is rendered in server-side templates, allowing template engine code execution.",
        remediation=(
            "1. Never render user input in templates directly\n"
            "2. Use sandboxed template engines (Jinja2 sandbox, Twig sandbox)\n"
            "3. Separate user data from template logic\n"
            "4. Use auto-escaping in templates\n"
            "5. Validate input against strict patterns before template rendering"
        ),
        references=["https://portswigger.net/web-security/server-side-template-injection"],
    ),
    "xxe": Remediation(
        cwe="CWE-611", title="XML External Entity (XXE)", severity="high",
        description="XML parser processes external entity definitions, allowing file reads, SSRF, or denial of service.",
        remediation=(
            "1. Disable DTD processing and external entities in XML parsers\n"
            "2. Use JSON instead of XML where possible\n"
            "3. Validate XML against a strict schema\n"
            "4. Use defusedxml library (Python) or equivalent\n"
            "5. Update XML parsers to latest versions"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"],
    ),
    "idor": Remediation(
        cwe="CWE-639", title="Insecure Direct Object Reference (IDOR)", severity="medium",
        description="Users can access resources belonging to other users by modifying identifier parameters.",
        remediation=(
            "1. Implement server-side authorization checks for every resource access\n"
            "2. Use indirect references (UUIDs, slugs) instead of sequential IDs\n"
            "3. Verify the authenticated user owns the requested resource\n"
            "4. Implement rate limiting on resource enumeration\n"
            "5. Log and alert on suspicious access patterns"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"],
    ),
    "auth_bypass": Remediation(
        cwe="CWE-287", title="Authentication Bypass", severity="high",
        description="Authentication mechanisms can be circumvented, granting unauthorized access.",
        remediation=(
            "1. Implement centralized authentication middleware\n"
            "2. Enforce authentication on all sensitive endpoints\n"
            "3. Use multi-factor authentication (MFA)\n"
            "4. Implement account lockout after failed attempts\n"
            "5. Audit all authentication code paths regularly"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
    ),
    "jwt": Remediation(
        cwe="CWE-347", title="Improper JWT Validation", severity="high",
        description="JSON Web Tokens are not properly validated, allowing signature bypass, algorithm confusion, or key leakage.",
        remediation=(
            "1. Always validate JWT signatures server-side\n"
            "2. Reject the 'none' algorithm\n"
            "3. Verify the 'alg' header matches expected algorithm\n"
            "4. Use strong, unique signing keys (RS256+ recommended)\n"
            "5. Set and validate expiration (exp), issuer (iss), audience (aud) claims\n"
            "6. Rotate signing keys periodically"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
    ),
    "open_redirect": Remediation(
        cwe="CWE-601", title="Open Redirect", severity="medium",
        description="Application redirects to user-controlled URLs without validation.",
        remediation=(
            "1. Validate redirect targets against a whitelist of allowed domains\n"
            "2. Use relative URLs for internal redirects\n"
            "3. Warn users when leaving the application\n"
            "4. Avoid URL parameters for redirect destinations"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
    ),
    "csrf": Remediation(
        cwe="CWE-352", title="Cross-Site Request Forgery (CSRF)", severity="high",
        description="State-changing operations can be triggered by malicious cross-origin requests.",
        remediation=(
            "1. Use anti-CSRF tokens in all state-changing forms\n"
            "2. Set SameSite cookie attribute (Strict or Lax)\n"
            "3. Validate Origin and Referer headers\n"
            "4. Require re-authentication for sensitive operations\n"
            "5. Use custom headers for AJAX API calls"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
    ),
    "crlf": Remediation(
        cwe="CWE-113", title="HTTP Header Injection (CRLF)", severity="medium",
        description="CRLF characters in user input allow injection of HTTP headers or response splitting.",
        remediation=(
            "1. Strip \\r and \\n characters from all user input used in headers\n"
            "2. Use language/framework APIs for setting headers (not string concatenation)\n"
            "3. Validate input against strict character whitelists"
        ),
        references=["https://owasp.org/www-community/attacks/HTTP_Header_Injection"],
    ),
    "file_upload": Remediation(
        cwe="CWE-434", title="Unrestricted File Upload", severity="high",
        description="Users can upload files without proper validation, potentially leading to code execution.",
        remediation=(
            "1. Validate file type by content (magic bytes), not just extension\n"
            "2. Set strict file size limits\n"
            "3. Store uploads outside the webroot\n"
            "4. Rename uploaded files to random names\n"
            "5. Scan uploads with antivirus before serving\n"
            "6. Set restrictive permissions on upload directory"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
    ),
    "deserialization": Remediation(
        cwe="CWE-502", title="Insecure Deserialization", severity="critical",
        description="Application deserializes untrusted data, potentially leading to remote code execution.",
        remediation=(
            "1. Avoid deserializing untrusted data entirely\n"
            "2. Use safe serialization formats (JSON, Protocol Buffers) instead of pickle\n"
            "3. Implement integrity checks (HMAC) on serialized data\n"
            "4. Use allowlists for permitted classes during deserialization\n"
            "5. Run deserialization code in isolated environments"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"],
    ),
    "ldap": Remediation(
        cwe="CWE-90", title="LDAP Injection", severity="high",
        description="User input is included in LDAP queries without sanitization.",
        remediation=(
            "1. Use parameterized LDAP queries\n"
            "2. Escape special LDAP characters (*, (, ), \\, NUL)\n"
            "3. Validate input against strict patterns\n"
            "4. Use least-privilege LDAP bind accounts"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"],
    ),
    "race_condition": Remediation(
        cwe="CWE-362", title="Race Condition", severity="high",
        description="Concurrent execution allows time-of-check to time-of-use (TOCTOU) vulnerabilities.",
        remediation=(
            "1. Use database-level locking (SELECT FOR UPDATE)\n"
            "2. Implement optimistic locking with version numbers\n"
            "3. Use atomic operations for critical sections\n"
            "4. Implement idempotency keys for financial operations\n"
            "5. Use serializable isolation level for critical transactions"
        ),
        references=["https://cwe.mitre.org/data/definitions/362.html"],
    ),
    "smuggle": Remediation(
        cwe="CWE-444", title="HTTP Request Smuggling", severity="high",
        description="Discrepancies in how front-end and back-end servers parse HTTP messages allow request smuggling.",
        remediation=(
            "1. Normalize HTTP request parsing across all servers\n"
            "2. Use HTTP/2 end-to-end (no HTTP/1.1 hop)\n"
            "3. Disable or strictly configure HTTP/1.1 pipelining\n"
            "4. Ensure consistent Content-Length and Transfer-Encoding handling\n"
            "5. Use a single, well-configured reverse proxy"
        ),
        references=["https://portswigger.net/web-security/request-smuggling"],
    ),
    "cors": Remediation(
        cwe="CWE-942", title="CORS Misconfiguration", severity="medium",
        description="Overly permissive CORS policies allow unauthorized cross-origin data access.",
        remediation=(
            "1. Whitelist specific allowed origins (never use wildcard with credentials)\n"
            "2. Validate Origin header server-side\n"
            "3. Set Access-Control-Allow-Credentials: true only when needed\n"
            "4. Limit Access-Control-Allow-Methods to necessary methods\n"
            "5. Set appropriate Access-Control-Max-Age"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html"],
    ),
    "secrets": Remediation(
        cwe="CWE-798", title="Hardcoded Credentials / Secret Exposure", severity="high",
        description="Secrets, API keys, or credentials are exposed in source code, configuration, or public files.",
        remediation=(
            "1. Move secrets to environment variables or dedicated secret managers\n"
            "2. Use .gitignore to prevent committing secrets\n"
            "3. Scan repositories with git-secrets or trufflehog\n"
            "4. Rotate all exposed credentials immediately\n"
            "5. Implement secret rotation policies\n"
            "6. Use short-lived tokens where possible"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
    ),
    "exposed_db": Remediation(
        cwe="CWE-200", title="Exposed Database", severity="critical",
        description="Database services are accessible from the public internet without authentication.",
        remediation=(
            "1. Restrict database access to application servers only (firewall rules)\n"
            "2. Never expose databases directly to the internet\n"
            "3. Use VPC/private networks for database access\n"
            "4. Enable authentication and use strong credentials\n"
            "5. Enable TLS for database connections"
        ),
        references=["https://cwe.mitre.org/data/definitions/200.html"],
    ),
    "default_creds": Remediation(
        cwe="CWE-798", title="Default Credentials", severity="critical",
        description="Services are running with default username/password combinations.",
        remediation=(
            "1. Change all default credentials during deployment\n"
            "2. Use configuration management to enforce credential changes\n"
            "3. Implement credential complexity requirements\n"
            "4. Disable default accounts entirely where possible\n"
            "5. Audit for default credentials regularly"
        ),
        references=["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    "takeover": Remediation(
        cwe="CWE-284", title="Subdomain Takeover", severity="critical",
        description="Dangling DNS records point to unclaimed third-party services, allowing an attacker to claim the subdomain.",
        remediation=(
            "1. Remove DNS records for services no longer in use\n"
            "2. Monitor for dangling CNAME records\n"
            "3. Use CAA records to restrict certificate issuance\n"
            "4. Implement automated DNS record auditing\n"
            "5. Claim subdomains on third-party services before attackers do"
        ),
        references=["https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Subdomain_Takeover"],
    ),
    "clickjacking": Remediation(
        cwe="CWE-1021", title="Clickjacking", severity="medium",
        description="Page can be embedded in an iframe, allowing UI redress attacks.",
        remediation=(
            "1. Set X-Frame-Options: DENY or SAMEORIGIN\n"
            "2. Implement Content-Security-Policy: frame-ancestors directive\n"
            "3. Use frame-busting JavaScript as fallback\n"
            "4. Avoid embedding sensitive pages in iframes"
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Prevention_Cheat_Sheet.html"],
    ),
    "mass_assign": Remediation(
        cwe="CWE-915", title="Mass Assignment", severity="medium",
        description="Framework automatically binds request parameters to model attributes, allowing privilege escalation.",
        remediation=(
            "1. Explicitly define which fields are allowed for assignment (strong parameters)\n"
            "2. Use DTOs or allowlists for user input\n"
            "3. Never bind request data directly to model objects\n"
            "4. Validate and sanitize all input before persistence"
        ),
        references=["https://cwe.mitre.org/data/definitions/915.html"],
    ),
    "sspp": Remediation(
        cwe="CWE-1321", title="Prototype Pollution", severity="high",
        description="JavaScript prototype chain can be modified via user-controlled __proto__ or constructor properties.",
        remediation=(
            "1. Use Object.create(null) for dictionary objects\n"
            "2. Freeze Object.prototype in sensitive contexts\n"
            "3. Validate/sanitize JSON input for __proto__, constructor, prototype keys\n"
            "4. Use Map instead of plain objects for user-controlled keys\n"
            "5. Keep dependencies updated"
        ),
        references=["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto"],
    ),
}


def get_remediation(vuln_type: str) -> Optional[Remediation]:
    """Look up remediation guidance by vulnerability type key.

    Args:
        vuln_type: Key into the ``REMEDIATIONS`` dict (e.g. ``"xss"``, ``"sqli"``).

    Returns:
        The matching :class:`Remediation`, or ``None`` if not found.
    """
    return REMEDIATIONS.get(vuln_type)


def get_all_remediations() -> Dict[str, Remediation]:
    """Return a shallow copy of the full ``REMEDIATIONS`` mapping.

    Useful for iterating over all known vulnerability types.
    """
    return dict(REMEDIATIONS)


def get_remediation_text(vuln_type: str) -> str:
    """Return a formatted remediation string for display.

    If no specific remediation exists for *vuln_type*, a generic best-practice
    message is returned instead.

    Returns:
        Multi-line string with CWE tag, title, and numbered fix steps.
    """
    r = REMEDIATIONS.get(vuln_type)
    if not r:
        return "No specific remediation available. Follow general security best practices."
    return f"[{r.cwe}] {r.title}\n\n{r.remediation}"


def has_remediation(vuln_type: str) -> bool:
    """Check whether a remediation entry exists for *vuln_type*."""
    return vuln_type in REMEDIATIONS
