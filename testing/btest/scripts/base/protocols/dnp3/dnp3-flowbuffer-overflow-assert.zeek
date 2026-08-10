# @TEST-DOC: Verify DNP3 cleans up a BinPAC flowbuffer allocation exception before connection teardown.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnp3/dnp3-flowbuffer-overflow-assert.pcap %INPUT
# @TEST-EXEC: test ! -s reporter.log

redef BinPAC::flowbuffer_capacity_max = 4096;

@load base/protocols/dnp3
