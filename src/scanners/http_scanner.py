"""Low-impact HTTP response-header checks."""

import ipaddress
import socket
from collections.abc import Mapping
from urllib.parse import SplitResult

import requests

from src.enums.severity import Severity
from src.scanners.scanner import Finding, ScanError, Scanner


class HttpScanner(Scanner):
    """Fetch one target URL and report a few basic response-header checks."""

    connect_timeout_seconds = 3
    read_timeout_seconds = 8

    def scan(self, target: SplitResult) -> list[Finding]:
        self._reject_non_public_dns(target.hostname or "", target.port or self._default_port(target.scheme))

        # Redirects are deliberately disabled. A redirect is returned as an
        # observation so the CLI never follows an unvalidated destination.
        try:
            with requests.Session() as session:
                # Do not route a user-supplied target through ambient proxy settings.
                session.trust_env = False
                with session.get(
                    target.geturl(),
                    timeout=(self.connect_timeout_seconds, self.read_timeout_seconds),
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                    headers={"User-Agent": "PostureCLI/0.1 (authorized low-impact checks)"},
                ) as response:
                    findings = self._check_headers(response.headers, target.scheme)
                    if 300 <= response.status_code < 400:
                        location = response.headers.get("Location", "(no Location header)")
                        findings.append(
                            Finding(
                                check_id="http.redirect",
                                severity=Severity.INFO,
                                title="The target returned a redirect",
                                description="The scanner did not follow the redirect. Review its destination before scanning it.",
                                evidence=f"HTTP {response.status_code}; Location: {location}",
                                remediation="If this is the intended website, run the scanner again with the final HTTPS URL.",
                            )
                        )
                    return findings
        except requests.exceptions.SSLError as exc:
            raise ScanError("TLS verification failed; the certificate or connection could not be trusted") from exc
        except requests.exceptions.Timeout as exc:
            raise ScanError("The website did not respond before the timeout") from exc
        except requests.exceptions.RequestException as exc:
            raise ScanError(f"The HTTP request failed: {exc}") from exc

    @staticmethod
    def _default_port(scheme: str) -> int:
        return 443 if scheme == "https" else 80

    @staticmethod
    def _reject_non_public_dns(hostname: str, port: int) -> None:
        """Reject hostnames resolving to private or special-use addresses.

        This is a local-CLI guard, not a complete DNS-rebinding defense: DNS is
        resolved again by the HTTP client when it connects. A hosted scanner
        must pin the validated address at connection time or enforce egress
        restrictions outside the process.
        """
        try:
            records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ScanError("The target hostname could not be resolved") from exc

        addresses = {record[4][0].split("%", 1)[0] for record in records}
        if not addresses:
            raise ScanError("The target hostname did not resolve to an address")

        for value in addresses:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ScanError("The target resolved to an invalid IP address") from exc
            if not address.is_global:
                raise ScanError("The target resolves to a private or reserved IP address")

    @staticmethod
    def _check_headers(headers: Mapping[str, str], scheme: str) -> list[Finding]:
        findings: list[Finding] = []

        def missing_header(
            header: str,
            check_id: str,
            severity: Severity,
            title: str,
            description: str,
            remediation: str,
        ) -> None:
            value = headers.get(header)
            if value is None:
                findings.append(
                    Finding(
                        check_id=check_id,
                        severity=severity,
                        title=title,
                        description=description,
                        evidence=f"The {header} response header was not present.",
                        remediation=remediation,
                    )
                )

        if scheme == "https":
            missing_header(
                "Strict-Transport-Security",
                "http.headers.hsts",
                Severity.MEDIUM,
                "HTTP Strict Transport Security is not enabled",
                "Without HSTS, browsers may use an unencrypted HTTP connection before learning the site should use HTTPS.",
                "After confirming HTTPS works across the domain, consider an HSTS policy with an appropriate max-age.",
            )

        missing_header(
            "Content-Security-Policy",
            "http.headers.csp",
            Severity.LOW,
            "Content Security Policy is not set",
            "A CSP can limit the sources from which a browser loads scripts and other resources. Its value depends on the site.",
            "Design and test a policy for the site's actual resources; start in report-only mode if needed.",
        )

        missing_header(
            "X-Content-Type-Options",
            "http.headers.content_type_options",
            Severity.LOW,
            "MIME sniffing protection is not set",
            "Browsers may infer a response's content type instead of relying only on its declared type.",
            "Set X-Content-Type-Options: nosniff where compatible with the site's content.",
        )

        missing_header(
            "Referrer-Policy",
            "http.headers.referrer_policy",
            Severity.INFO,
            "Referrer behavior is not explicitly configured",
            "A referrer policy controls how much URL information browsers include when navigating away from the site.",
            "Choose a policy appropriate for the site's privacy and navigation needs, such as strict-origin-when-cross-origin.",
        )

        csp = headers.get("Content-Security-Policy", "").lower()
        has_frame_protection = "frame-ancestors" in csp or "X-Frame-Options" in headers
        if not has_frame_protection:
            findings.append(
                Finding(
                    check_id="http.headers.frame_protection",
                    severity=Severity.LOW,
                    title="No browser framing restriction was found",
                    description="The response does not advertise a common control against other sites embedding it in a frame.",
                    evidence="Neither CSP frame-ancestors nor X-Frame-Options was present.",
                    remediation="If the site should not be embedded, configure CSP frame-ancestors; use X-Frame-Options for older browser support if needed.",
                )
            )

        return findings
