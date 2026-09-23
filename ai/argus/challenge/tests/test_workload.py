import base64
import io

import pytest

from argus import workload


def test_workload_emits_one_result_then_keeps_process_alive(monkeypatch, capsys):
    result = {
        "kind": "argus-runtime-result",
        "profile": "team-namespace",
        "resource": "argus-public",
        "status": "ok",
        "isolation_verified": True,
        "verification_result": None,
    }
    monkeypatch.setattr(workload, "run", lambda: result)

    def stop(seconds):
        assert seconds == 3600
        raise StopIteration

    monkeypatch.setattr(workload.time, "sleep", stop)
    with pytest.raises(StopIteration):
        workload.main()

    output = capsys.readouterr().out
    assert output.count("argus-runtime-result") == 1
    assert output.count("\n") == 1


@pytest.mark.parametrize(
    ("profile", "forbidden", "allowed", "value"),
    [
        ("team-namespace", ("secrets", "argus-protected"), ("configmaps", "argus-public"), {}),
        (
            "team-namespace-elevated",
            ("configmaps", "argus-public"),
            ("secrets", "argus-protected"),
            {"data": {"verification_result": base64.b64encode(b"flag").decode()}, "metadata": {"namespace": "team-a", "name": "argus-protected"}},
        ),
    ],
)
def test_run_checks_counterpart_denial_before_allowed_resource(
    monkeypatch, profile, forbidden, allowed, value
):
    monkeypatch.setenv("ARGUS_RUNTIME_PROFILE", profile)
    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: io.StringIO("team-a"))
    denied = []
    monkeypatch.setattr(workload, "_expect_forbidden_resource", lambda *args: denied.append(args))
    monkeypatch.setattr(workload, "_read_resource", lambda *args: value)

    result = workload.run()

    assert denied == [("team-a", *forbidden)]
    assert result["resource"] == allowed[1]
    assert result["isolation_verified"] is True
    assert result["verification_result"] == ("flag" if profile == "team-namespace-elevated" else None)
