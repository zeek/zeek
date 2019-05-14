# @TEST-EXEC: zeek -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: btest-diff netcontrol_catch_release.log
# @TEST-EXEC: btest-diff .stdout

@load base/frameworks/netcontrol

redef NetControl::catch_release_intervals = vector(1sec, 2sec, 2sec);

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	NetControl::activate(netcontrol_debug, 0);
	}

global pc: count = 0;

event new_packet(c: connection, p: pkt_hdr)
	{
	if ( ++pc == 1 )
		NetControl::drop_address_catch_release(10.0.0.1);
	}

event NetControl::catch_release_forgotten(a: addr, bi: NetControl::BlockInfo)
	{
	print "Forgotten: ", a, bi;
	}
