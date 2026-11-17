# @TEST-DOC: Without libbrotlidec, Content-Encoding: br bodies pass through as is and raise a weird.
#
# @TEST-REQUIRES: ! grep -q "#define USE_BROTLI" $BUILD/zeek-config.h
#
# @TEST-EXEC: zeek -b -r $TRACES/http/content-encoding-brotli.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log

@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/http
