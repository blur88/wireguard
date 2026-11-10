from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class PeerTelemetry:
    """Decoupled runtime telemetry data for a WireGuard peer."""

    status_label: str = "Unavailable"
    latest_handshake: str = "Unavailable"
    transfer_rx: str = "Unavailable"
    transfer_tx: str = "Unavailable"
    is_available: bool = False


@runtime_checkable
class TelemetryProvider(Protocol):
    """Protocol for querying runtime WireGuard peer telemetry."""

    def get_peer_telemetry(self, peer_id: str) -> PeerTelemetry:
        """Return runtime telemetry for the requested peer identifier."""
        ...


class NoOpTelemetryProvider:
    """Decoupled Phase 1 telemetry provider returning truthful 'Unavailable' status."""

    def get_peer_telemetry(self, peer_id: str) -> PeerTelemetry:
        """Always return explicit Unavailable status without privileged kernel access."""
        return PeerTelemetry(
            status_label="Unavailable",
            latest_handshake="Unavailable",
            transfer_rx="Unavailable",
            transfer_tx="Unavailable",
            is_available=False,
        )
