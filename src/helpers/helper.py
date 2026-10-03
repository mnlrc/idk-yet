"""Small helpers for normalizing and validating CLI targets."""

import ipaddress
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit


class Helper:
    """URL helpers kept separate from network and scanner logic."""

    @staticmethod
    def parse_url(data: str) -> SplitResult:
        """Normalize a domain or HTTP(S) URL into a parsed URL.

        A bare domain defaults to HTTPS. Only standard HTTP/HTTPS ports are
        accepted. The path and query are preserved; fragments are discarded
        because browsers do not send them to servers.

        Raises ValueError when input is malformed or uses an unsupported URL.
        """
        if not isinstance(data, str):
            raise ValueError("Target must be text")

        target = data.strip()
        if not target or any(ord(char) < 33 for char in target):
            raise ValueError("Target is empty or contains whitespace/control characters")

        if "://" not in target:
            target = f"https://{target}"

        try:
            parsed = urlsplit(target)
            hostname = parsed.hostname
            port = parsed.port  # Accessing this also validates malformed ports.
        except ValueError as exc:
            raise ValueError("Target has an invalid host or port") from exc

        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS targets are supported")
        if not hostname:
            raise ValueError("Target must include a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing credentials are not supported")

        default_port = 80 if scheme == "http" else 443
        if port is not None and port != default_port:
            raise ValueError(f"Only the standard {scheme.upper()} port is supported")

        normalized_host = Helper._normalize_host(hostname)
        # Re-add brackets for IPv6 literals when constructing a network location.
        netloc = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
        path = parsed.path or "/"
        normalized = urlunsplit((scheme, netloc, path, parsed.query, ""))
        return urlsplit(normalized)

    @staticmethod
    def check_url(data: str) -> bool:
        """Return whether *data* can be parsed as a supported target."""
        try:
            Helper.parse_url(data)
        except ValueError:
            return False
        return True

    @staticmethod
    def _normalize_host(hostname: str) -> str:
        """Normalize a DNS name and reject obviously local/non-public hosts."""
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            try:
                ascii_host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise ValueError("Hostname is not valid IDNA") from exc

            if len(ascii_host) > 253 or not ascii_host:
                raise ValueError("Hostname length is invalid")
            labels = ascii_host.split(".")
            label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$|^[a-z0-9]$")
            if any(not label_pattern.fullmatch(label) for label in labels):
                raise ValueError("Hostname format is invalid")
            if ascii_host == "localhost" or ascii_host.endswith((".localhost", ".local", ".internal")):
                raise ValueError("Local hostnames are not valid scan targets")
            return ascii_host

        if not address.is_global:
            raise ValueError("Private, loopback, and reserved IP addresses are not valid targets")
        return address.compressed
