from wireguard_dashboard.auth.rate_limit import LoginRateLimiter


def test_rate_limiter_allows_up_to_max_attempts() -> None:
    current_time = 1000.0
    limiter = LoginRateLimiter(max_attempts=5, window_seconds=60.0, clock=lambda: current_time)

    client_id = "192.168.1.50"
    for _ in range(5):
        assert limiter.is_allowed(client_id) is True
        limiter.record_failure(client_id)

    # 6th attempt is blocked
    assert limiter.is_allowed(client_id) is False


def test_rate_limiter_resets_after_window_expires() -> None:
    current_time = 1000.0
    limiter = LoginRateLimiter(max_attempts=5, window_seconds=60.0, clock=lambda: current_time)

    client_id = "192.168.1.50"
    for _ in range(5):
        limiter.record_failure(client_id)

    assert limiter.is_allowed(client_id) is False

    # Advance clock past the 60s window
    current_time = 1061.0
    assert limiter.is_allowed(client_id) is True


def test_rate_limiter_resets_counter_on_success() -> None:
    current_time = 1000.0
    limiter = LoginRateLimiter(max_attempts=5, window_seconds=60.0, clock=lambda: current_time)

    client_id = "192.168.1.50"
    for _ in range(4):
        limiter.record_failure(client_id)

    # Successful login resets the failure counter
    limiter.record_success(client_id)

    for _ in range(5):
        assert limiter.is_allowed(client_id) is True
        limiter.record_failure(client_id)

    # Now 6th attempt after reset is blocked
    assert limiter.is_allowed(client_id) is False


def test_independent_rate_limit_identities() -> None:
    current_time = 1000.0
    limiter = LoginRateLimiter(max_attempts=5, window_seconds=60.0, clock=lambda: current_time)

    client_a = "10.0.0.1"
    client_b = "10.0.0.2"

    for _ in range(5):
        limiter.record_failure(client_a)

    assert limiter.is_allowed(client_a) is False
    assert limiter.is_allowed(client_b) is True


def test_retry_after_calculation() -> None:
    current_time = 1000.0
    limiter = LoginRateLimiter(max_attempts=5, window_seconds=60.0, clock=lambda: current_time)
    client_id = "192.168.1.10"

    for _ in range(5):
        limiter.record_failure(client_id)

    # Oldest attempt was at 1000.0, expires at 1060.0
    assert limiter.retry_after_seconds(client_id) == 60

    current_time = 1025.0
    assert limiter.retry_after_seconds(client_id) == 35


def test_untrusted_client_cannot_spoof_x_forwarded_for() -> None:
    from starlette.requests import Request

    from wireguard_dashboard.auth.rate_limit import get_client_ip

    scope = {
        "type": "http",
        "client": ("203.0.113.195", 12345),
        "headers": [(b"x-forwarded-for", b"198.51.100.1")],
    }
    request = Request(scope)
    # Untrusted proxy: X-Forwarded-For ignored
    assert get_client_ip(request, trusted_proxies=None) == "203.0.113.195"
    assert get_client_ip(request, trusted_proxies={"127.0.0.1"}) == "203.0.113.195"


def test_trusted_proxy_x_forwarded_for_respected() -> None:
    from starlette.requests import Request

    from wireguard_dashboard.auth.rate_limit import get_client_ip

    scope = {
        "type": "http",
        "client": ("10.0.0.1", 12345),
        "headers": [(b"x-forwarded-for", b"198.51.100.1, 10.0.0.1")],
    }
    request = Request(scope)
    # Trusted proxy 10.0.0.1 forwards real client IP
    assert get_client_ip(request, trusted_proxies={"10.0.0.1"}) == "198.51.100.1"
