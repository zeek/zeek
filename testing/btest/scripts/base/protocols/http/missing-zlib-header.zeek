# This tests an issue where some web servers don't 
# include an appropriate ZLIB header on deflated 
# content.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/missing-zlib-header.pcap %INPUT
# @TEST-EXEC: btest-diff http.log

@load base/protocols/http
