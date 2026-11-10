import subprocess
import sys
import zipfile
from pathlib import Path


def test_wheel_packaging_includes_templates_and_static_assets(tmp_path: Path) -> None:
    """Smoke test ensuring package build includes non-Python assets (templates and static CSS)."""
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()

    repo_root = Path(__file__).resolve().parent.parent

    # Build wheel into temporary directory
    build_cmd = [
        sys.executable,
        "-m",
        "pip",
        "wheel",
        "--no-deps",
        "-w",
        str(dist_dir),
        str(repo_root),
    ]

    res = subprocess.run(build_cmd, capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, (
        f"pip wheel build failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}"
    )

    wheel_files = list(dist_dir.glob("*.whl"))
    assert len(wheel_files) == 1, f"Expected 1 wheel, found: {wheel_files}"

    wheel_path = wheel_files[0]
    with zipfile.ZipFile(wheel_path, "r") as zf:
        namelist = zf.namelist()

        # Verify python source files
        assert "wireguard_dashboard/app.py" in namelist
        assert "wireguard_dashboard/config.py" in namelist

        # Verify non-python package data
        assert "wireguard_dashboard/templates/base.html" in namelist
        assert "wireguard_dashboard/static/style.css" in namelist
