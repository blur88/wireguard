"""Test helpers and shared assertions."""

from collections.abc import Mapping

EXPECTED_SECURITY_HEADERS: dict[str, str] = {
    "content-security-policy": (
        "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store, no-cache, must-revalidate, private",
}


def assert_security_headers(
    headers: Mapping[str, str], expected_headers: dict[str, str] = EXPECTED_SECURITY_HEADERS
) -> None:
    """Helper verifying that expected security headers are present with exact values."""
    for header_name, expected_value in expected_headers.items():
        assert header_name in headers, f"Missing header: {header_name}"
        assert headers[header_name] == expected_value, (
            f"Header {header_name} expected '{expected_value}', got '{headers[header_name]}'"
        )
