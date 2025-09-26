## api.zeek
##
## Sample events to be invoked by api.js
module MyAPI;

export {
	global print_msg: event(msg: string, ts: time &default=network_time());
}

event MyAPI::print_msg(msg: string, ts: time) {
	print "ZEEK", "print_msg", ts, msg;
}

@load ./api.js
