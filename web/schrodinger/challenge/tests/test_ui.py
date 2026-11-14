from fastapi.testclient import TestClient

from schrodinger.portal.app import create_app


def test_registry_and_independent_views_render(tmp_path):
    client = TestClient(create_app(tmp_path))
    for path, heading in (
        ("/", "Registry"),
        ("/inspections", "Inspections"),
        ("/runtime", "Runtime"),
        ("/policy", "Policy"),
        ("/api-help", "API Reference"),
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert heading.encode() in response.content
        assert b"/static/js/" in response.content

    package = client.get("/api/packages").json()["items"][0]
    detail = client.get(f"/packages/{package['artifact_id']}")
    assert detail.status_code == 200
    assert b"Package files" in detail.content
    report = client.get(f"/packages/{package['artifact_id']}/inspector")
    assert report.status_code == 200
    assert b"Inspector report" in report.content
    assert client.get("/static/css/app.css").status_code == 200
    for script in ("common.js", "registry.js", "package.js", "inspector.js", "inspections.js", "runtime.js"):
        response = client.get(f"/static/js/{script}")
        assert response.status_code == 200
        if script != "common.js":
            assert b"/api/" in response.content


def test_browser_upload_then_opens_package_view(tmp_path):
    client = TestClient(create_app(tmp_path))
    script = client.get("/static/js/registry.js").text

    upload = script.index('api("/api/packages", { method: "POST", body: form })')
    open_package = script.index('window.location.assign(`/packages/${encodeURIComponent(result.package_id)}?uploaded=1`)')
    assert upload < open_package
    assert "/inspection" not in script

    package_script = client.get("/static/js/package.js").text
    package_page = client.get("/packages/" + client.get("/api/packages").json()["items"][0]["artifact_id"]).text
    assert "No package inventory has been recorded." in package_script
    assert "Run an inspection to record" not in package_script
    assert "Run inspection" in package_page
    assert "Astra Package Exchange" in package_page
    assert "Open inspector report" in package_page
    assert 'job.flag' in package_script
    assert "released.textContent = job.flag" in package_script
    help_page = client.get("/api-help").text.lower()
    assert "api reference" in help_page
    assert "compare the recorded inventory" not in help_page
    assert "different package views" not in help_page


def test_seeded_package_names_and_copy(tmp_path):
    client = TestClient(create_app(tmp_path))
    packages = client.get("/api/packages").json()["items"]
    assert {item["package_name"] for item in packages} == {
        "astra-http-client", "astra-metrics", "astra-log-format", "astra-auth-client",
    }
    assert b"Registered Python packages." in client.get("/registry").content
    assert b"Inspection history for registered packages." in client.get("/inspections").content
    assert b"Recent runtime sessions." in client.get("/runtime").content
    assert b"Astra Python Package Inspection Policy" in client.get("/api/policy").content
