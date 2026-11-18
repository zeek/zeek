# @TEST-DOC: On musl, the zeek binary requests an 8 MiB default thread stack through its PT_GNU_STACK header; musl's own default is 128 KiB.
#
# @TEST-REQUIRES: ldd --version 2>&1 | grep -qi musl
# @TEST-REQUIRES: which readelf
#
# @TEST-EXEC: readelf -lW "$(which zeek)" | awk '/GNU_STACK/ {print $6}' > out
# @TEST-EXEC: btest-diff out
