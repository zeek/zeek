# @TEST-DOC: Verifies that the VLAN-aware conntuple builder correctly distinguishes colliding 5-tuples that only differ in their vlan tagging.
#
# @TEST-EXEC: zeek -b -r $TRACES/conntuple/tuple-collision-vlan.pcap %INPUT
# @TEST-EXEC: zeek-cut -m ts  uid id.orig_h id.orig_p id.resp_h id.resp_p id.vlan id.inner_vlan <conn.log >conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut

@load base/protocols/conn
@load protocols/conntuple/vlan
