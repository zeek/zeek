# @TEST-DOC: Verify a long SMB1 Logoff-AndX chain with non-advancing offsets is rejected.
#
# @TEST-EXEC: zeek -b -r $TRACES/smb/smb1-logoff-andx-no-advance.pcap %INPUT >out 2>err
# @TEST-EXEC: test ! -s err
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/smb
@load base/frameworks/notice/weird
