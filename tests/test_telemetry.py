from wireguard_dashboard.telemetry.provider import (
    NoOpTelemetryProvider,
    PeerTelemetry,
    TelemetryProvider,
)


def test_telemetry_provider_protocol_conformance() -> None:
    provider = NoOpTelemetryProvider()
    assert isinstance(provider, TelemetryProvider)


def test_noop_telemetry_reports_unavailable_without_fabricated_metrics() -> None:
    provider = NoOpTelemetryProvider()
    telemetry = provider.get_peer_telemetry("peer1")

    assert isinstance(telemetry, PeerTelemetry)
    assert telemetry.status_label == "Unavailable"
    assert telemetry.latest_handshake == "Unavailable"
    assert telemetry.transfer_rx == "Unavailable"
    assert telemetry.transfer_tx == "Unavailable"
    assert telemetry.is_available is False


def test_noop_telemetry_does_not_leak_or_accept_arbitrary_active_states() -> None:
    provider = NoOpTelemetryProvider()
    for peer_id in ["peer1", "peer_phone", "unknown"]:
        t = provider.get_peer_telemetry(peer_id)
        assert t.is_available is False
        assert t.status_label == "Unavailable"
