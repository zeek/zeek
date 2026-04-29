# @TEST-REQUIRES: is-windows
# @TEST-REQUIRES: zeek --test -h >/dev/null
# @TEST-EXEC: SOCKET_FILE_PATH=${TMPDIR:-/tmp} ZEEK_SEED_FILE= zeek --test --test-case='Flare/*' >&2
#
# @TEST-DOC: Run Flare unit tests using AF_UNIX sockets on Windows.
#
# Setting SOCKET_FILE_PATH causes Flare to use Unix domain sockets instead of
# loopback UDP.  Flare is exercised via doctest TEST_CASEs that construct a
# Flare, Fire() it, and verify Extinguish() returns correctly.  The env var
# must be set before process start because the value is cached with
# std::call_once on first use.
