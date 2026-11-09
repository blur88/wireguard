import shutil
import socket
import subprocess
import time
from typing import Generator
import urllib.error
import urllib.request
import uuid
import pytest


def is_docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return res.returncode == 0
    except Exception:
        return False


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_healthz(url: str, timeout: float = 15.0) -> bool:
    """Poll the /healthz endpoint until it returns HTTP 200 with {'status': 'ok'} or times out."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8")
                    if '{"status":"ok"}' in body.replace(" ", ""):
                        return True
        except Exception:
            time.sleep(0.5)
    return False


pytestmark = pytest.mark.skipif(
    not is_docker_available(),
    reason="Docker daemon is not available in test environment",
)

IMAGE_TAG = "wireguard-dashboard-test:ci"


@pytest.fixture(scope="module")
def docker_image() -> Generator[str, None, None]:
    """Build the Docker image once for container tests."""
    build = subprocess.run(
        ["docker", "build", "-t", IMAGE_TAG, "."],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if build.returncode != 0:
        pytest.fail(f"Docker build failed:\nSTDOUT: {build.stdout}\nSTDERR: {build.stderr}")

    yield IMAGE_TAG

    # Cleanup image
    subprocess.run(["docker", "rmi", "-f", IMAGE_TAG], capture_output=True)


def test_container_runs_as_non_root(docker_image: str) -> None:
    res = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "id", docker_image, "-u"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert res.returncode == 0
    uid = res.stdout.strip()
    assert uid != "0", f"Container must not run as root (UID 0), got UID: {uid}"


def test_container_default_port_healthz(docker_image: str) -> None:
    host_port = get_free_port()
    container_name = f"wg-test-default-{host_port}"

    run_cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "-p", f"127.0.0.1:{host_port}:8080",
        "--security-opt", "no-new-privileges:true",
        "--read-only",
        "--tmpfs", "/tmp",
        docker_image,
    ]

    subprocess.run(run_cmd, check=True, capture_output=True)

    try:
        url = f"http://127.0.0.1:{host_port}/healthz"
        if not _wait_for_healthz(url):
            logs = subprocess.run(["docker", "logs", container_name], capture_output=True, text=True)
            pytest.fail(f"Container failed to respond to /healthz.\nLogs:\n{logs.stdout}\n{logs.stderr}")

    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


def test_container_custom_port(docker_image: str) -> None:
    host_port = get_free_port()
    container_port = 9050
    container_name = f"wg-test-custom-{host_port}"

    run_cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "-e", f"PORT={container_port}",
        "-p", f"127.0.0.1:{host_port}:{container_port}",
        docker_image,
    ]

    subprocess.run(run_cmd, check=True, capture_output=True)

    try:
        url = f"http://127.0.0.1:{host_port}/healthz"
        if not _wait_for_healthz(url):
            logs = subprocess.run(["docker", "logs", container_name], capture_output=True, text=True)
            pytest.fail(f"Container on custom PORT={container_port} failed.\nLogs:\n{logs.stdout}\n{logs.stderr}")

    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


def test_container_invalid_port_fails_safely(docker_image: str) -> None:
    container_suffix = uuid.uuid4().hex[:8]
    container_name = f"wg-test-invalid-{container_suffix}"

    run_cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "-e", "PORT=invalid_port_999999",
        docker_image,
    ]

    subprocess.run(run_cmd, check=True, capture_output=True)

    try:
        time.sleep(2)
        inspect_res = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", container_name],
            capture_output=True,
            text=True,
            check=True,
        )
        running, exit_code = inspect_res.stdout.strip().split()
        assert running == "false", "Container should not continue running with invalid PORT"
        assert exit_code != "0", f"Container exit code should be non-zero, got {exit_code}"

        logs = subprocess.run(["docker", "logs", container_name], capture_output=True, text=True)
        assert (
            "Configuration error" in logs.stderr
            or "Invalid PORT" in logs.stderr
            or "Configuration error" in logs.stdout
            or "Invalid PORT" in logs.stdout
        )

    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
