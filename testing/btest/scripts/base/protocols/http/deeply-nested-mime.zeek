# @TEST-DOC: HTTP POST request with 100 nestesd message/rfc822 entities, causing an analysis depth of 200 or so, Zeek stops at 100 and produces a weird.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/deeply-nested-mime.pcap %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/http
