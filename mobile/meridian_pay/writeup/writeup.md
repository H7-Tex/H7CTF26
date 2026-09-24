# Meridian Pay - writeup

Meridian Pay ships an Android client (`meridian-pay-3.2.1.apk`) and a per-team staging
API. The client authenticates the device silently on first launch, so there is no
password to reuse; every flag is minted by the team's own backend, so nothing is
shareable. Four findings, four flags.

Point the app at the instance URL and tap Connect. Decompile the APK
(`jadx meridian-pay-3.2.1.apk`) and read the manifest and the four source classes.

## v1 - exported deep-link redirected into the authenticated WebView

`AndroidManifest.xml` exports `RouterActivity` with a `meridianpay://open` scheme (and an
`https://links.meridianpay.io/open` App Link). `RouterActivity` takes its `url` query
parameter and forwards it verbatim into `WebViewActivity`. `WebViewActivity` attaches the
cached `Authorization: Bearer <session>` and the `X-Meridian-Client` attestation header to
any URL that starts with the app's own origin, then calls `loadUrl`.

That header is what gates `GET /api/v1/internal/promo`; an ordinary browser navigation
cannot set it. The public page `/api/v1/promo/public` links to the internal enrollment
path, so the endpoint is discoverable. Redirect the trusted WebView at it:

```
adb shell am start -a android.intent.action.VIEW \
  -d "meridianpay://open?url=<INSTANCE>/api/v1/internal/promo"
```

The flag renders in the in-app WebView. This is intent redirection: an exported component
forwards attacker-controlled input into a privileged, already-authenticated context.

## v2 - exported content-provider path traversal

`ExportProvider` is exported (`android:exported="true"`) and exists to share receipt
files. `openFile()` joins the URI path onto `files/receipts` with no canonicalization:

```java
File base = new File(getContext().getFilesDir(), "receipts");
String name = path.startsWith("/files/") ? path.substring("/files/".length()) : path;
return ParcelFileDescriptor.open(new File(base, name), MODE_READ_ONLY);
```

`..%2F..%2F` escapes the sandbox and reads any app-private file. Steal the cached session
token out of shared preferences:

```
adb shell content read --uri \
  "content://com.meridian.pay.export/files/..%2F..%2Fshared_prefs%2Fsession.xml"
```

`session.xml` contains `session_token`. With it, call the profile endpoint the app never
touches:

```
curl <INSTANCE>/api/v1/accounts/me -H "Authorization: Bearer <TOKEN>"
```

The `onboarding_memo` field carries the flag.

## v3 - broken object-level authorization (BOLA / IDOR)

`GET /api/v1/accounts/{id}/statement` performs no ownership check. The demo session is
account `1001`; walking to the corporate treasury account `1002` returns its statement,
whose audit memo carries the flag:

```
curl <INSTANCE>/api/v1/accounts/1002/statement -H "Authorization: Bearer <TOKEN>"
```

## v4 - mass-assignment to privilege escalation

`PATCH /api/v1/profile` blindly copies every field of the request body onto the user
record, including `role`. The admin ledger requires `role == admin`:

```
curl -X PATCH <INSTANCE>/api/v1/profile -H "Authorization: Bearer <TOKEN>" \
  -H 'Content-Type: application/json' -d '{"role":"admin"}'
curl <INSTANCE>/api/v1/admin/ledger -H "Authorization: Bearer <TOKEN>"
```

The ledger export carries the flag.

## Notes

- Nothing is in the APK: all four flags are minted server-side per team and never appear
  in the client. Decompiling only reveals the techniques (endpoints, the traversal, the
  header injection), never a flag.
- The intended order is v1 (deep-link, no session material needed) then v2 (steal the
  session), which unlocks v3 and v4. A player who reverses the client fully may reach some
  flags by other means; that is still a real finding on their own instance.
