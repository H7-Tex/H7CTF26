"""Reference player path: establish the old worker, then use it after rollout."""
from __future__ import annotations

import argparse
import re
import time
import zipfile
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError, sync_playwright


def wait_for(page, expression: str, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if page.evaluate(expression):
                return
        except Exception:
            pass
        page.wait_for_timeout(100)
    raise RuntimeError(f"Relay did not reach expected state: {expression}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Relay instance base URL")
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--expect-flag", help=argparse.SUPPRESS)
    parser.add_argument("--ignore-cert-spki", help=argparse.SUPPRESS)
    args = parser.parse_args()
    base = args.url.rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit("Relay must be reached through HTTPS outside localhost development")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    origins: set[str] = set()

    with sync_playwright() as playwright:
        try:
            chromium_args = [f"--ignore-certificate-errors-spki-list={args.ignore_cert_spki}"] if args.ignore_cert_spki else []
            browser = playwright.chromium.launch(headless=not args.headed, args=chromium_args)
        except PlaywrightError:
            browser = playwright.chromium.launch(channel="chrome", headless=not args.headed, args=chromium_args)
        context = browser.new_context(service_workers="allow", accept_downloads=True)
        context.on("request", lambda req: origins.add(f"{urlsplit(req.url).scheme}://{urlsplit(req.url).netloc}"))
        page = context.new_page()
        page.on("console", lambda message: print(f"browser console [{message.type}]: {message.text}"))
        page.goto(base, wait_until="domcontentloaded")
        wait_for(page, "document.querySelector('meta[name=build-id]')?.content === '2026.09.24.1'", args.timeout)
        wait_for(page, "navigator.serviceWorker.getRegistration('/').then(r=>r?.active?.scriptURL.endsWith('/sw-2026.09.24.1.js'))", args.timeout)
        if not page.evaluate("navigator.serviceWorker.controller?.scriptURL.endsWith('/sw-2026.09.24.1.js')"):
            page.reload(wait_until="domcontentloaded")
        wait_for(page, "navigator.serviceWorker.controller?.scriptURL.endsWith('/sw-2026.09.24.1.js')", args.timeout)
        assert page.evaluate("fetch('/api/meta').then(r=>r.json()).then(x=>x.api_version)") == "1.0"
        print("[PASS] player's fresh profile established active/controller=legacy before rollout")

        contract = page.evaluate("""async () => {
          const manifest=await fetch('/__release/manifest.json',{cache:'no-store'}).then(r=>r.json());
          const asset=Object.entries(manifest.assets).find(([path])=>path.includes('report-package-v1.json'));
          if(!asset) throw new Error('historical package metadata is absent from the release manifest');
          const [path,digest]=asset; const response=await fetch(path,{cache:'no-store'});
          const bytes=await response.arrayBuffer();
          const actual=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
          if(actual!==digest) throw new Error('historical compatibility asset digest does not match');
          return JSON.parse(new TextDecoder().decode(bytes));
        }""")
        assert "commissioning" in contract["profiles"]["complete"]["material"]
        page.locator("button[data-job-id='JOB-3887']").click()
        wait_for(page, "document.querySelector('[data-report-profile]')", args.timeout)
        available_profiles = page.locator("[data-report-profile] option").evaluate_all("options => options.map(option => option.value)")
        if available_profiles != ["summary", "record"]:
            raise RuntimeError(f"unexpected v1 report-package choices: {available_profiles}")
        saved = page.evaluate("""async () => {
          const endpoint='/api/jobs/JOB-3887/report-preference';
          const current=await fetch(endpoint,{cache:'no-store'});
          if(!current.ok || !current.headers.get('ETag')) throw new Error('v1 report setting is unavailable');
          const response=await fetch(endpoint,{method:'PUT',cache:'no-store',headers:{'Content-Type':'application/json','If-Match':current.headers.get('ETag')},body:JSON.stringify({contract:'relay.report-package/v1',profile:'complete'})});
          if(!response.ok) throw new Error(`v1 setting was rejected: ${response.status}`);
          const saved=await response.json();
          const worker=navigator.serviceWorker.controller;
          if(!worker) throw new Error('legacy worker is not controlling the v1 page');
          const reply=await new Promise((resolve,reject)=>{const channel=new MessageChannel();const timer=setTimeout(()=>reject(new Error('worker did not save the package setting')),3000);channel.port1.onmessage=event=>{clearTimeout(timer);resolve(event.data)};worker.postMessage({type:'RELAY_REPORT_PACKAGE_SAVE',profile:'complete',revision:saved.revision},[channel.port2])});
          if(reply?.status!=='saved') throw new Error('legacy worker did not persist the historical package setting');
          return saved;
        }""")
        if saved["report_package"].get("profile") != "complete" or saved["revision"] < 1:
            raise RuntimeError("the crafted v1 preference was not accepted")
        wait_for(page, "fetch('/api/jobs/JOB-3887/report-preference',{cache:'no-store'}).then(r=>r.json()).then(x=>x.report_package.profile==='complete'&&x.revision>0)", args.timeout)
        key_state = page.evaluate("""() => new Promise(resolve => {const c=new MessageChannel();c.port1.onmessage=e=>resolve(e.data);navigator.serviceWorker.controller.postMessage({type:'RELAY_KEY_STATUS'},[c.port2])})""")
        if not key_state.get("available") or key_state.get("private_key_extractable") is not False:
            raise RuntimeError("legacy offline signing key was not initialized in the browser")
        print("[PASS] historical v1 package choice and non-extractable offline key are stored by the legacy worker")

        page.locator("#sync-button").click()
        wait_for(page, "document.querySelector('meta[name=build-id]')?.content === '2026.09.24.2'", args.timeout)
        wait_for(page, "fetch('/api/meta',{cache:'no-store'}).then(r=>r.json()).then(x=>x.api_version==='2.0')", args.timeout)
        wait_for(page, "navigator.serviceWorker.getRegistration('/').then(r=>r?.waiting?.scriptURL.endsWith('/sw-2026.09.24.2.js')&&r.active?.scriptURL.endsWith('/sw-2026.09.24.1.js')&&navigator.serviceWorker.controller?.scriptURL.endsWith('/sw-2026.09.24.1.js'))", args.timeout)
        print("[PASS] genuine browser skew: frontend=v2 api=v2 active/controller=legacy waiting=current")

        page.locator("button[data-job-id='JOB-3887']").click()
        page.get_by_label("Report detail").select_option("record")
        wait_for(page, "fetch('/api/jobs/JOB-3887/report-preference',{cache:'no-store'}).then(r=>r.json()).then(x=>x.report_package.scope==='record'&&x.revision)", args.timeout)
        saved = page.evaluate("fetch('/api/jobs/JOB-3887/report-preference',{cache:'no-store'}).then(r=>r.json()).then(x=>x.revision)")
        wait_for(page, f"fetch('/api/jobs/JOB-3887/report-preference',{{cache:'no-store'}}).then(r=>r.json()).then(x=>x.dispatch.snapshot_revision==={int(saved)})", args.timeout)
        preference = page.evaluate("fetch('/api/jobs/JOB-3887/report-preference',{cache:'no-store'}).then(r=>r.json())")
        if preference["dispatch"]["snapshot_revision"] != saved:
            raise RuntimeError("dispatch snapshot did not capture the saved preference")

        page.locator("#sync-button").click()
        page.get_by_role("button", name="Send queued updates").wait_for(state="visible", timeout=args.timeout * 1000)
        wait_for(page, "document.querySelector('#reconciliation-receipt')?.textContent.includes('Sync reference')", args.timeout)
        print("[PASS] staged semantic conversion returned the sync reference")
        report_before = page.evaluate("fetch('/api/jobs/JOB-3887',{cache:'no-store'}).then(r=>r.json()).then(x=>x.job)")
        if "report" in report_before:
            raise RuntimeError("outbox staging published before deliberate replay")
        print("[PASS] v2 preview was staged by the stale worker; staging alone did not publish")
        page.get_by_role("button", name="Send queued updates").click()
        wait_for(page, "fetch('/api/jobs/JOB-3887',{cache:'no-store'}).then(r=>r.json()).then(x=>x.job.report?.report_package?.profile==='complete')", args.timeout)
        print("[PASS] deliberate MessageChannel replay published the historical complete package")

        page.locator("button[data-job-id='JOB-3887']").click()
        page.get_by_role("button", name="Prepare report package").click()
        link = page.get_by_role("link", name="Download report package")
        link.wait_for(state="visible", timeout=args.timeout * 1000)
        with page.expect_download(timeout=args.timeout * 1000) as download:
            link.click()
        with zipfile.ZipFile(download.value.path()) as archive:
            note = archive.read("attachments/commissioning-note.txt").decode()
        found = re.search(r"H7CTF\{[^}\r\n]+\}", note)
        if not found or note.count(found.group()) != 1:
            raise RuntimeError("the normal export did not contain exactly one runtime flag")
        if args.expect_flag and found.group() != args.expect_flag:
            raise RuntimeError("the exported flag did not match the expected test value")
        if origins != {origin}:
            raise RuntimeError(f"browser requests escaped the Relay origin: {sorted(origins)}")
        cookie = next((item for item in context.cookies(base) if item["name"] == "relay_session"), None)
        if not cookie or not cookie["httpOnly"] or (parsed.scheme == "https" and not cookie["secure"]):
            raise RuntimeError("Relay session cookie protections are missing")
        print("[PASS] ordinary report export returned exactly one runtime flag")
        print(f"origin={origin} relay_session.httpOnly=true relay_session.secure={str(cookie['secure']).lower()}")
        print(f"final flag: {found.group()}")
        context.close()
        browser.close()


if __name__ == "__main__":
    main()
