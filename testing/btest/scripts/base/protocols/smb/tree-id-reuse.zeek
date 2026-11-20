# @TEST-DOC: Regression test for #6011. A single SMB connection with multiple sessions and two Tree Connect Responses holding tree_id 1.
#
# @TEST-EXEC: zeek -b -C -r $TRACES/smb/tree-id-reuse.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m smb_files.log
# @TEST-EXEC: btest-diff-cut -m smb_mapping.log
#
# @TEST-EXEC: test ! -f analyzer.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/smb
