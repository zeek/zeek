# @TEST-DOC: Verify a long SMB1 Logoff-AndX chain hits the maximum depth.
#
# @TEST-EXEC: zeek -b -r $TRACES/smb/smb1-logoff-andx-advance.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/smb
@load base/frameworks/notice/weird
