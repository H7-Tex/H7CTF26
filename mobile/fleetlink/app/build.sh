#!/bin/bash
set -e
cd "$(dirname "$0")"

SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
BT="$SDK/build-tools/35.0.0"
AJAR="$SDK/platforms/android-35/android.jar"
JHOME="$HOME/.local/share/mise/installs/java/temurin-17"
JAVAC="$JHOME/bin/javac"
KEYTOOL="$JHOME/bin/keytool"
OUT=build
APKNAME=fleetlink-4.1.0.apk

rm -rf "$OUT"
mkdir -p "$OUT/gen" "$OUT/obj" "$OUT/apk"

if [ ! -f debug.keystore ]; then
    "$KEYTOOL" -genkeypair -keystore debug.keystore -storepass android -keypass android \
        -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Android Debug,O=Android,C=US"
fi

aapt2 compile --dir res -o "$OUT/res.zip"
aapt2 link -o "$OUT/apk/base.apk" -I "$AJAR" --manifest AndroidManifest.xml \
    --java "$OUT/gen" --min-sdk-version 24 --target-sdk-version 34 "$OUT/res.zip"
"$JAVAC" -source 17 -target 17 -nowarn -Xlint:none -cp "$AJAR" -d "$OUT/obj" \
    $(find src -name '*.java') $(find "$OUT/gen" -name 'R.java')
d8 --min-api 24 --lib "$AJAR" --output "$OUT/apk" $(find "$OUT/obj" -name '*.class')
( cd "$OUT/apk" && zip -q -j base.apk classes.dex )
"$BT/zipalign" -f 4 "$OUT/apk/base.apk" "$OUT/apk/aligned.apk"
apksigner sign --ks debug.keystore --ks-pass pass:android \
    --ks-key-alias androiddebugkey --key-pass pass:android \
    --out "../handout/$APKNAME" "$OUT/apk/aligned.apk"
apksigner verify --print-certs "../handout/$APKNAME" | head -1
echo "built ../handout/$APKNAME"
