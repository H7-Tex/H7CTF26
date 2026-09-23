import os
import importlib.util
from pathlib import Path

import pytest
import httpx


_SOLVER_PATH = Path(__file__).parents[3] / "solution" / "solve.py"
_SPEC = importlib.util.spec_from_file_location("argus_two_instance_solver", _SOLVER_PATH)
_SOLVER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SOLVER)


_PORTALS = [item.strip().rstrip("/") for item in os.getenv("ARGUS_H7_PORTAL_URLS", "").split(",") if item.strip()]
pytestmark = pytest.mark.skipif(
    len(_PORTALS) != 2,
    reason="requires two fresh H7 Anvil instance Portal URLs",
)


def test_h7_instances_keep_integrations_and_dynamic_flags_isolated():
    first, second = _PORTALS
    first_result = _SOLVER.solve(first)["verification_result"]
    second_result = _SOLVER.solve(second)["verification_result"]
    assert first_result.startswith("H7CTF{") and first_result.endswith("}")
    assert second_result.startswith("H7CTF{") and second_result.endswith("}")
    assert first_result != second_result

    with httpx.Client(timeout=15) as client:
        package = client.get(first + "/api/packages").json()["packages"][0]["package_id"]
        created = client.post(first + "/api/integrations", json={"package_id": package})
        assert created.status_code == 201
        integration_id = created.json()["integration_id"]
        other_integrations = client.get(second + "/api/integrations")
        assert other_integrations.status_code == 200
        assert integration_id not in {
            item.get("integration_id") for item in other_integrations.json().get("integrations", [])
        }
