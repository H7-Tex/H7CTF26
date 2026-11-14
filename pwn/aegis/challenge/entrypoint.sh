#!/bin/sh
# seal the per-instance flag and serve the diagnostic console over TCP, one process per connection.
set -e
# NB: keep the default in its own var. Inlining a brace-containing default as
# "${FLAG:-H7CTF{...}}" makes the shell close the expansion at the first '}' and
# append the second as a literal -> every flag gets a stray trailing brace.
DEFAULT_FLAG='H7CTF{aegis_gateway_local_test_flag}'
printf '%s\n' "${FLAG:-$DEFAULT_FLAG}" > /flag
chmod 644 /flag
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"/usr/local/bin/gateway",stderr
