import time
from collections.abc import Callable

from starlette.requests import Request


class LoginRateLimiter:
    """In-memory sliding-window rate limiter for failed login attempts.

    Suitable for single-worker deployment. Tracks failure timestamps per client identifier.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: float = 60.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._clock = clock if clock is not None else time.monotonic
        self._failures: dict[str, list[float]] = {}

    def _prune(self, key: str, now: float) -> list[float]:
        threshold = now - self.window_seconds
        valid = [t for t in self._failures.get(key, []) if t > threshold]
        if valid:
            self._failures[key] = valid
        else:
            self._failures.pop(key, None)
        return valid

    def is_allowed(self, key: str) -> bool:
        """Check if client has not exceeded failure threshold in the current window."""
        now = self._clock()
        valid = self._prune(key, now)
        return len(valid) < self.max_attempts

    def record_failure(self, key: str) -> None:
        """Record a failed login attempt for the client."""
        now = self._clock()
        valid = self._prune(key, now)
        valid.append(now)
        self._failures[key] = valid

    def record_success(self, key: str) -> None:
        """Reset failure counter for the client upon successful authentication."""
        self._failures.pop(key, None)

    def retry_after_seconds(self, key: str) -> int:
        """Calculate the remaining lockout seconds until an attempt becomes eligible."""
        now = self._clock()
        valid = self._prune(key, now)
        if len(valid) < self.max_attempts:
            return 0
        oldest = min(valid)
        remaining = (oldest + self.window_seconds) - now
        return max(1, int(remaining + 0.999))


def get_client_ip(request: Request, trusted_proxies: set[str] | None = None) -> str:
    """Extract client IP address safely, preventing spoofed headers from untrusted proxies."""
    remote_host = request.client.host if request.client else "127.0.0.1"

    if trusted_proxies and remote_host in trusted_proxies:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            # Parse rightmost untrusted hop
            ips = [ip.strip() for ip in xff.split(",") if ip.strip()]
            for ip in reversed(ips):
                if ip not in trusted_proxies:
                    return ip
            if ips:
                return ips[0]

    return remote_host
