# @TEST-DOC: Tests the limitation for the number of sections in a PE file
#
# @TEST-EXEC: zeek -b -r $TRACES/pe/pe-excessive-sections.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m analyzer.log
# @TEST-EXEC: btest-diff-cut -m files.log

@load base/files/pe
@load base/protocols/http
