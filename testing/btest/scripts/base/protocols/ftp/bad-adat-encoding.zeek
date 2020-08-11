# @TEST-EXEC: zeek -b -C -r $TRACES/globus-url-copy-bad-encoding.trace %INPUT
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/ftp
@load base/frameworks/notice/weird
