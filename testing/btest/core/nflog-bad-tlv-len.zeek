# @TEST-DOC: A non-payload NFLOG TLV whose length runs past the remaining bytes is flagged as nflog_bad_tlv_len instead of reading the next TLV header out of bounds.
# @TEST-EXEC: zeek -b -Cr $TRACES/nflog-bad-tlv-len.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m name addl source weird.log

@load base/frameworks/notice/weird
