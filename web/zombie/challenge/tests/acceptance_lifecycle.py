"""Exercise genuine player-owned v1 to v2 Service Worker update detection."""
from __future__ import annotations

import time

from playwright.sync_api import sync_playwright

from acceptance_phase2 import launch, start_server, stop_server, unused_port


def wait_page(page, expression: str, timeout: int = 30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = page.evaluate(expression)
            if result:
                return result
        except Exception:
            pass
        page.wait_for_timeout(100)
    raise AssertionError(f"Timed out waiting for browser state: {expression}")


def test_player_profile_keeps_legacy_controller_when_current_waits():
    process, base = start_server(unused_port())
    try:
        with sync_playwright() as playwright:
            browser = launch(playwright)
            context = browser.new_context(service_workers="allow")
            page = context.new_page()
            page.goto(base, wait_until="domcontentloaded")
            wait_page(page, "document.querySelector('meta[name=build-id]')?.content==='2026.09.24.1'")
            wait_page(page, "navigator.serviceWorker.getRegistration('/').then(r=>r?.active?.scriptURL.endsWith('/sw-2026.09.24.1.js'))")
            if not page.evaluate("navigator.serviceWorker.controller?.scriptURL.endsWith('/sw-2026.09.24.1.js')"):
                page.reload(wait_until="domcontentloaded")
            wait_page(page, "navigator.serviceWorker.controller?.scriptURL.endsWith('/sw-2026.09.24.1.js')")
            assert page.evaluate("fetch('/api/meta').then(r=>r.json()).then(x=>x.api_version)") == "1.0"
            print("[PASS] player's clean browser installs and controls v1 legacy worker")

            page.locator("button[data-job-id='JOB-3887']").click()
            page.locator("[data-report-profile] option").first.wait_for(state="attached")
            options = page.locator("[data-report-profile] option").evaluate_all("items => items.map(item => item.value)")
            assert options == ["summary", "record"]
            saved = page.evaluate("""async () => {
              const endpoint='/api/jobs/JOB-3887/report-preference';
              const current=await fetch(endpoint,{cache:'no-store'});
              const response=await fetch(endpoint,{method:'PUT',headers:{'Content-Type':'application/json','If-Match':current.headers.get('ETag')},body:JSON.stringify({contract:'relay.report-package/v1',profile:'complete'})});
              if(!response.ok) throw new Error(`v1 preference rejected: ${response.status}`);
              const saved=await response.json();
              const worker=navigator.serviceWorker.controller;
              const result=await new Promise(resolve=>{const channel=new MessageChannel();channel.port1.onmessage=event=>resolve(event.data);worker.postMessage({type:'RELAY_REPORT_PACKAGE_SAVE',profile:'complete',revision:saved.revision},[channel.port2])});
              return {saved,result};
            }""")
            assert saved["saved"]["report_package"]["profile"] == "complete"
            assert saved["result"] == {"status": "saved"}
            wait_page(page, "fetch('/api/jobs/JOB-3887/report-preference').then(r=>r.json()).then(x=>x.report_package.profile==='complete')")
            print("[PASS] v1 UI offers only summary/record; crafted preference and worker metadata are saved separately")
            page.locator("#sync-button").click()
            wait_page(page, "document.querySelector('meta[name=build-id]')?.content==='2026.09.24.2'")
            wait_page(page, "fetch('/api/meta',{cache:'no-store'}).then(r=>r.json()).then(x=>x.api_version==='2.0')")
            tuple_state = wait_page(page, "navigator.serviceWorker.getRegistration('/').then(r=>r?.active?.scriptURL.endsWith('/sw-2026.09.24.1.js')&&r?.waiting?.scriptURL.endsWith('/sw-2026.09.24.2.js')&&navigator.serviceWorker.controller?.scriptURL.endsWith('/sw-2026.09.24.1.js'))")
            assert tuple_state
            worker_builds = page.evaluate("""async () => {
              const registration=await navigator.serviceWorker.getRegistration('/');
              const inspect=worker=>new Promise(resolve=>{const channel=new MessageChannel();channel.port1.onmessage=event=>resolve(event.data);worker.postMessage({type:'RELAY_VERSION'},[channel.port2])});
              const [active,waiting]=await Promise.all([inspect(registration.active),inspect(registration.waiting)]);
              return {active,waiting};
            }""")
            assert worker_builds["active"]["build"] == "2026.09.24.1"
            assert worker_builds["active"]["script"] == "/sw-2026.09.24.1.js"
            assert worker_builds["waiting"]["build"] == "2026.09.24.2"
            assert worker_builds["waiting"]["script"] == "/sw-2026.09.24.2.js"
            assert "generation" not in worker_builds["active"] and "version" not in worker_builds["active"]
            assert all(page.evaluate("Promise.all(['/sw-2026.09.24.1.js','/sw-2026.09.24.2.js'].map(path=>fetch(path,{cache:'no-store'}).then(response=>response.ok)))"))
            print("[PASS] genuine ServiceWorkerRegistration state: active=legacy controller=legacy waiting=current")
            print("[PASS] rollout preserves old client while current worker waits")
            page.reload(wait_until="domcontentloaded")
            wait_page(page, "document.querySelector('meta[name=build-id]')?.content==='2026.09.24.2'")
            wait_page(page, "navigator.serviceWorker.getRegistration('/').then(r=>r?.active?.scriptURL.endsWith('/sw-2026.09.24.1.js')&&r?.waiting?.scriptURL.endsWith('/sw-2026.09.24.2.js')&&navigator.serviceWorker.controller?.scriptURL.endsWith('/sw-2026.09.24.1.js'))")
            print("[PASS] v2 navigation/reload remains controlled by the old active worker")
            page.close()
            page = context.new_page()
            page.goto(base, wait_until="domcontentloaded")
            wait_page(page, "navigator.serviceWorker.getRegistration('/').then(r=>r?.active?.scriptURL.endsWith('/sw-2026.09.24.2.js')&&navigator.serviceWorker.controller?.scriptURL.endsWith('/sw-2026.09.24.2.js'))")
            update = page.evaluate("""async () => {const old=await fetch('/api/jobs/JOB-3887/report-preference');const r=await fetch('/api/jobs/JOB-3887/report-preference',{method:'PUT',headers:{'Content-Type':'application/json','If-Match':old.headers.get('ETag')},body:JSON.stringify({contract:'relay.report-package/v2',scope:'record'})});return r.json()}""")
            wait_page(page, f"fetch('/api/jobs/JOB-3887/report-preference',{{cache:'no-store'}}).then(r=>r.json()).then(x=>x.dispatch.snapshot_revision==={update['revision']})")
            page.locator("#sync-button").click()
            page.wait_for_timeout(500)
            assert page.locator("#flush-button").count() == 0
            assert page.evaluate("fetch('/api/jobs/JOB-3887').then(r=>r.json()).then(x=>x.job.status)") == "Draft"
            print("[PASS] current worker leaves the same v2 preview nonpersistent and unpublished")
            context.close()
            browser.close()
    finally:
        stop_server(process)


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main(["-s", __file__]))
