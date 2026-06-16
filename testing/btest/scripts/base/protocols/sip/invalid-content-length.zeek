# @TEST-DOC: Verify that invalid (non-numeric) Content-Length values produce weirds.

# @TEST-EXEC: zeek -b -r $TRACES/sip/invalid-content-length.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m method status_code request_body_len response_body_len sip.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log

@load base/protocols/sip
@load base/frameworks/notice/weird
