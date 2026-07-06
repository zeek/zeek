# @TEST-DOC: Test notice generation on intel hit
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff notice.log

@load frameworks/intel/do_notice
@load frameworks/intel/seen/where-locations

event zeek_init()
	{
	Intel::insert([$indicator="10.0.0.1", $indicator_type=Intel::ADDR, $meta=[
		$source="source1", $do_notice=T, $if_in=Conn::IN_ORIG]]);
	Intel::insert([$indicator="10.0.0.2", $indicator_type=Intel::ADDR, $meta=[
		$source="source1", $do_notice=T, $if_in=Intel::IN_ANYWHERE]]);
	Intel::insert([$indicator="10.0.0.3", $indicator_type=Intel::ADDR, $meta=[
		$source="source1", $do_notice=T]]);

	# Notice expected
	Intel::seen([$host=10.0.0.1, $where=Conn::IN_ORIG]);
	Intel::seen([$host=10.0.0.2, $where=Conn::IN_RESP]);
	Intel::seen([$host=10.0.0.3, $where=Conn::IN_RESP]);
	# No notice expected
	Intel::seen([$host=192.168.1.23, $where=Conn::IN_RESP]);
	}