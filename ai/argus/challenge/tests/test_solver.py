import importlib.util
from pathlib import Path

import pytest


_SOLVER_PATH = Path(__file__).parents[2] / "solution" / "solve.py"
_SPEC = importlib.util.spec_from_file_location("argus_reference_solver", _SOLVER_PATH)
_SOLVER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SOLVER)
SolverError = _SOLVER.SolverError
_delivery_count = _SOLVER._delivery_count


class DeliveryPortal:
    def __init__(self, response):
        self.response = response

    def json(self, method, path):
        assert method == "GET"
        assert path == "/api/integrations/integration/deliveries"
        return self.response


def test_delivery_count_uses_total_not_capped_delivery_list():
    client = DeliveryPortal({"delivery_count": 194, "deliveries": [{}] * 128})

    assert _delivery_count(client, "integration") == 194


@pytest.mark.parametrize("count", [None, True, -1, "194"])
def test_delivery_count_rejects_invalid_total(count):
    client = DeliveryPortal({"delivery_count": count, "deliveries": []})

    with pytest.raises(SolverError, match="valid delivery_count"):
        _delivery_count(client, "integration")
