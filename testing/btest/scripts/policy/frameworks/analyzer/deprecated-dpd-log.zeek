# @TEST-DOC: Test the deprecated dpd log with tests from before its removal.
# @TEST-EXEC: zeek -r $TRACES/ftp/ftp-missing-space-after-reply-code.pcap %INPUT
# @TEST-EXEC: mv dpd.log dpd-ftp-missing-space-after-reply-code.log
# @TEST-EXEC: zeek -r $TRACES/ftp/ftp-invalid-reply-code.pcap %INPUT
# @TEST-EXEC: mv dpd.log dpd-ftp-invalid-reply-code.log
# @TEST-EXEC: zeek -r $TRACES/http/http-11-request-then-cruft.pcap %INPUT
# @TEST-EXEC: mv dpd.log dpd-http-11-request-then-cruft.log
# @TEST-EXEC: zeek -C -r $TRACES/tunnels/gtp/gtp9_unknown_or_too_short_payload.pcap %INPUT
# @TEST-EXEC: mv dpd.log dpd-gtp9_unknown_or_too_short_payload.log
# @TEST-EXEC: zeek -r $TRACES/dce-rpc/ntlm-empty-av-sequence.pcap %INPUT
# @TEST-EXEC: mv dpd.log dpd-ntlm-empty-av-sequence.log
# @TEST-EXEC: btest-diff dpd-ftp-missing-space-after-reply-code.log
# @TEST-EXEC: btest-diff dpd-ftp-invalid-reply-code.log
# @TEST-EXEC: btest-diff dpd-http-11-request-then-cruft.log
# @TEST-EXEC: btest-diff dpd-gtp9_unknown_or_too_short_payload.log
# @TEST-EXEC: btest-diff dpd-ntlm-empty-av-sequence.log

@load frameworks/analyzer/deprecated-dpd-log.zeek
