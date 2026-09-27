import os
import pytest


@pytest.mark.integration
def test_studionet_requires_explicit_opt_in():
    """Live consensus is run only when the operator supplies RUN_STUDIONET=1."""
    if os.getenv("RUN_STUDIONET") != "1":
        pytest.skip("set RUN_STUDIONET=1 to run against real Studionet validators")
    assert os.getenv("GENLAYER_CHAIN_ID", "61999") == "61999"

