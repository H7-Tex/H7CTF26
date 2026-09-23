import os
import importlib.util
from pathlib import Path

import pytest

_SOLVER_PATH = Path(__file__).parents[3] / "solution" / "solve.py"
_SPEC = importlib.util.spec_from_file_location("argus_h7_solver", _SOLVER_PATH)
_SOLVER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SOLVER)
solve = _SOLVER.solve


pytestmark = pytest.mark.skipif(
    not os.getenv("ARGUS_H7_PORTAL_URL"),
    reason="requires a fresh live H7 Anvil instance",
)


def test_solver_recovers_anvil_dynamic_flag_from_fresh_instance():
    deployment = solve(os.environ["ARGUS_H7_PORTAL_URL"])
    flag = deployment["verification_result"]
    assert flag.startswith("H7CTF{") and flag.endswith("}")
