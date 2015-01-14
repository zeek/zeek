
module Comm;

export {

	const endpoint_name = "" &redef;

	type SendFlags: record {
		self: bool &default = F;
		peers: bool &default = T;
		unsolicited: bool &default = F;
	};
}
