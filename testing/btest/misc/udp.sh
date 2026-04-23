# @TEST-DOC: Check that the Zeek::PacketSourceUDP plugin is available on FreeBSD and Linux
#
# @TEST-REQUIRES: is-linux || is-freebsd
# @TEST-EXEC: zeek -NN Zeek::PacketSourceUDP >out
# @TEST-EXEC: btest-diff out
