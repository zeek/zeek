# @TEST-EXEC: zeek -b %INPUT >output

module SSH;

export {
	redef enum Log::ID += { LOG };
}
