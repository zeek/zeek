# @TEST-DOC: Verify VLAN of 0 in double-tagged QinQ traffic gets logged with the two ways to log it
#
# @TEST-EXEC: zeek -br $TRACES/http-qinq-0.pcap %INPUT
# @TEST-EXEC: zeek-cut -m id.ctx.vlan id.ctx.inner_vlan vlan inner_vlan <conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut

@load frameworks/conn_key/vlan_fivetuple
@load protocols/conn/vlan-logging
