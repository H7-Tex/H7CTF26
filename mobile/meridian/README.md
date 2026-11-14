# Meridian Pay

**Category:** mobile  **Difficulty:** hard  **Author:** abu

> Meridian Pay is a neobank that shipped in a hurry and trusts everyone: the client trusts the server, the server trusts the client, and both trust the phone underneath. Four separate cracks are hiding in that arrangement, some in the app and some in the API behind it, one flag each.
>
> Move fast, break banks.

Handout: `handout/meridian-pay-3.2.1.apk.zip`. Per-team Flask API (`backend/`) on port 8080 with four dynamic flags (`FLAG_V1`..`FLAG_V4`). Run it with a single worker, since v4 changes in-memory role state.

## Solution

Install the APK, enter the instance URL and tap Connect. The app authenticates the device silently and caches a session, so there's no password to find. Then jadx it and read the manifest and the handful of classes.

### v1: deep link into the authenticated WebView

`RouterActivity` is exported with a `meridianpay://open` scheme and forwards its `url` parameter straight into `WebViewActivity`. That WebView attaches the cached `Authorization: Bearer` token and the `X-Meridian-Client` attestation header to any URL on the app's own origin.

That header is what gates `GET /api/v1/internal/promo`, and `/api/v1/promo/public` links to it. A normal browser can't send the header, but the app's WebView will:

```
adb shell am start -a android.intent.action.VIEW \
  -d "meridianpay://open?url=<INSTANCE>/api/v1/internal/promo"
```

The flag renders in the app.

### v2: provider path traversal

`ExportProvider` is exported to share receipts, and `openFile()` joins the URI path onto `files/receipts` without canonicalizing it. `..%2F` walks right out:

```
adb shell content read --uri \
  "content://com.meridian.pay.export/files/..%2F..%2Fshared_prefs%2Fsession.xml"
```

`session.xml` has `session_token`. With that, `GET /api/v1/accounts/me` (which the app never calls) returns an `onboarding_memo` with the second flag.

### v3: BOLA

`GET /api/v1/accounts/{id}/statement` doesn't check ownership. We're account `1001`; the treasury account is `1002`:

```
curl <INSTANCE>/api/v1/accounts/1002/statement -H "Authorization: Bearer <TOKEN>"
```

The audit memo has the flag.

### v4: mass assignment

`PATCH /api/v1/profile` copies every field in the body onto the user, `role` included:

```
curl -X PATCH <INSTANCE>/api/v1/profile -H "Authorization: Bearer <TOKEN>" \
  -H 'Content-Type: application/json' -d '{"role":"admin"}'
curl <INSTANCE>/api/v1/admin/ledger -H "Authorization: Bearer <TOKEN>"
```

The ledger export has the last flag.

`solution/solve.sh http://<host>:<port>` runs all four (v1 you read off the device screen). The intended order is v1, then v2 to steal the session for v3 and v4, but if you reverse the client fully you can reach some of them other ways. All four flags are per team and none are in the APK.
