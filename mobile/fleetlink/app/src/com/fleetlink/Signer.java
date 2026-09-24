package com.fleetlink;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Map;
import java.util.TreeMap;

// request signing for the FleetLink API. every call carries X-Device-Id, X-Ts and X-Sig.
public class Signer {
    private static final String APP_SECRET = "fleetlink_signing_pepper_v3";

    public static class Signed {
        public String query;
        public String ts;
        public String sig;
        public String deviceId;
    }

    public static Signed sign(String method, String path, TreeMap<String, String> params, String deviceId) throws Exception {
        StringBuilder q = new StringBuilder();
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (q.length() > 0) q.append("&");
            q.append(e.getKey()).append("=").append(e.getValue());
        }
        String ts = String.valueOf(System.currentTimeMillis() / 1000L);
        String canonical = method + "\n" + path + "\n" + q + "\n" + ts;

        byte[] key = MessageDigest.getInstance("SHA-256")
                .digest((APP_SECRET + ":" + deviceId).getBytes("UTF-8"));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] raw = mac.doFinal(canonical.getBytes("UTF-8"));

        Signed s = new Signed();
        s.query = q.toString();
        s.ts = ts;
        s.sig = hex(raw);
        s.deviceId = deviceId;
        return s;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
