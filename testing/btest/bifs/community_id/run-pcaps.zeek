# Test imported from original zeek-community-id repository.
#
# Crank through a set of pcaps and verify the Community ID inputs and
# outputs. Since each output line is triggered by a connection state
# removal in Zeek, the ordering of sets of those events can change
# across Zeek releases, and we don't care about the order (just the
# values involved), we sort the output files.

# @TEST-EXEC: bash %INPUT

set -ex

for pcap in $(cd $TRACES/communityid && ls *.pcap); do
    zeek -r $TRACES/communityid/$pcap test-community-id-v1.zeek | sort >$pcap.out
    btest-diff $pcap.out
done

@TEST-START-FILE test-community-id-v1.zeek
event connection_state_remove(c: connection) {
	print c$id, community_id_v1(c$id);
}
@TEST-END-FILE
