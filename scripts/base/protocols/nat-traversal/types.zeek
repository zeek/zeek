module NATTraversal;

export {
	## Result codes used by nat-traversal.log. Result codes from protocols should be
	## mapped into these.
	type ResultCode: enum {
		SUCCESS = 0,
		PROTOCOL_ERROR = 1,
		POLICY_FAILURE = 2,
		TIMEOUT = 3,
		UNKNOWN = 4,
	};
}
