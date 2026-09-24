# FleetLink - writeup

FleetLink is the Android app delivery drivers use to pull trip assignments (v4.1.0) plus a
signed REST API. Point the Server field at your instance and tap "Load my trips" - the app
signs the request and the backend accepts it. The goal is the dispatcher-only fleet
manifest, which the app never requests. Its value is the flag, minted per team.

## The signing scheme

Decompile the APK (`jadx fleetlink-4.1.0.apk`) and read `com/fleetlink/Signer.java`:

```java
private static final String APP_SECRET = "fleetlink_signing_pepper_v3";
...
String canonical = method + "\n" + path + "\n" + q + "\n" + ts;      // q = sorted k=v&...
byte[] key = MessageDigest.getInstance("SHA-256")
        .digest((APP_SECRET + ":" + deviceId).getBytes("UTF-8"));
Mac mac = Mac.getInstance("HmacSHA256");
mac.init(new SecretKeySpec(key, "HmacSHA256"));
// X-Sig = hex(mac.doFinal(canonical)), plus X-Device-Id and X-Ts
```

So: `key = SHA256(APP_SECRET + ":" + deviceId)`, and
`X-Sig = HMAC-SHA256(key, METHOD\nPATH\nSORTED_QUERY\nTS)`.

## Why you must reverse it (not replay)

The signature covers the query string and a fresh timestamp. Capturing the app's
`GET /api/v1/trips?scope=mine` request gets you a valid signature for *that* request only;
it will not validate for a different path or a different `scope`. To call the privileged
endpoint you must produce a new signature, which means reimplementing the scheme. `deviceId`
is attacker-chosen: the server derives the key from whatever `X-Device-Id` you send, so you
sign with your own device id.

## Forging the privileged call

The app only ever sends `scope=mine`. Asking the manifest endpoint with a valid signature
but `scope=mine` returns the value you need to know:

```
scope 'mine' cannot list the full fleet; requires scope=all (dispatcher)
```

Re-sign with `scope=all`:

```python
key = sha256(b"fleetlink_signing_pepper_v3:" + device_id).digest()
canonical = f"GET\n/api/v1/fleet/manifest\nscope=all\n{ts}"
sig = hmac.new(key, canonical.encode(), sha256).hexdigest()
# GET /api/v1/fleet/manifest?scope=all  with X-Device-Id/X-Ts/X-Sig
```

The response's `dispatcher_manifest_signing_key` is the flag. See `solution/solve.py`.

## Notes

- The flag is minted per team by the backend and lives only behind the signed, privileged
  call. The APK carries the signing scheme and the endpoint, never a flag.
- Two rungs in one: reverse the request-signing (so you can talk to the API at all on your
  own terms), then broken function/scope access control (`scope=all` is enforced only by a
  value the app never sends).
