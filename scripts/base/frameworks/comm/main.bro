
module Comm;

export {

	const endpoint_name = "" &redef;

	type SendFlags: record {
		self: bool &default = F;
		peers: bool &default = T;
		unsolicited: bool &default = F;
	};

	type Data: record {
		d: opaque of Comm::Data &optional;
	};

	type EventArgs: record {
		name: string &optional;  # nil for invalid event/args.
		args: vector of Comm::Data;
	};
}
