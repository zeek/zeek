# @TEST-EXEC: bro -b %INPUT >output

module SSH;

export {
	redef enum Log::ID += { LOG };
}
