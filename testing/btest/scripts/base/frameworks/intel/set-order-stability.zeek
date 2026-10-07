# @TEST-DOC: Set columns in intel.log must be stable across different hash seeds.
#
# @TEST-EXEC: ZEEK_SEED_FILE= ZEEK_SEED_VALUES="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21" zeek -b %INPUT
# @TEST-EXEC: $SCRIPTS/diff-remove-first-timestamp <intel.log >intel-a.log
# @TEST-EXEC: rm intel.log
#
# @TEST-EXEC: ZEEK_SEED_FILE= ZEEK_SEED_VALUES="99 98 97 96 95 94 93 92 91 90 89 88 87 86 85 84 83 82 81 80 79" zeek -b %INPUT
# @TEST-EXEC: $SCRIPTS/diff-remove-first-timestamp <intel.log >intel-b.log
#
# @TEST-EXEC: diff intel-a.log intel-b.log

@load base/frameworks/intel

redef enum Intel::Where += { SOMEWHERE };

event zeek_init()
	{
	Intel::insert([$indicator="192.168.142.1", $indicator_type=Intel::ADDR,
	               $meta=[$source="source-addr"]]);
	Intel::insert([$indicator="192.168.142.0/24", $indicator_type=Intel::SUBNET,
	               $meta=[$source="source-subnet-24"]]);
	Intel::insert([$indicator="192.168.128.0/18", $indicator_type=Intel::SUBNET,
	               $meta=[$source="source-subnet-18"]]);

	Intel::seen([$host=192.168.142.1, $where=SOMEWHERE]);
	}
