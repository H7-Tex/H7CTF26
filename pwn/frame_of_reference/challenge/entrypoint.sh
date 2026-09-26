#!/bin/sh
set -e
DEFAULT_FLAG='H7CTF{frame_of_reference_local_test_flag}'
export FLAG="${FLAG:-$DEFAULT_FLAG}"
exec socat TCP-LISTEN:"${PORT:-1337}",reuseaddr,fork EXEC:"/usr/local/bin/attest",stderr
