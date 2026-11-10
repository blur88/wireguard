import logging
import os
from unittest import mock

import pytest

from wireguard_dashboard.app import create_app
from wireguard_dashboard.main import main


def test_create_app_fails_securely_on_missing_credentials() -> None:
    with mock.patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError, match="DASHBOARD_PASSWORD.*required"):
            create_app()


def test_main_exits_with_nonzero_code_on_missing_credentials(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with mock.patch.dict(os.environ, {}, clear=True):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Configuration error" in captured.err


def test_auth_disabled_logs_prominent_security_warning(caplog: pytest.LogCaptureFixture) -> None:
    with mock.patch.dict(os.environ, {"AUTH_DISABLED": "true"}, clear=True):
        with caplog.at_level(logging.WARNING):
            app = create_app()
            assert app is not None
            assert any(
                "SECURITY WARNING" in record.message and "AUTH_DISABLED=true" in record.message
                for record in caplog.records
            )
