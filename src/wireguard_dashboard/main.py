import sys

import uvicorn

from wireguard_dashboard.config import get_settings


def main() -> None:
    """Application CLI entrypoint."""
    try:
        settings = get_settings()
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    uvicorn.run(
        "wireguard_dashboard.app:create_app",
        factory=True,
        host="0.0.0.0",
        port=settings.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
