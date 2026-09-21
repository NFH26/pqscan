import os
import subprocess

import pytest


@pytest.mark.network
def test_verify_hosts_network():
    if os.environ.get("RUN_NETWORK") != "1":
        pytest.skip("set RUN_NETWORK=1 to run network verification")
    result = subprocess.run(["./pqc", "verify", "--input", "hosts.csv", "--pq", "--scores"], check=False, capture_output=True)
    output = result.stdout.decode()
    assert "DIFF" not in output
    assert result.returncode == 0
