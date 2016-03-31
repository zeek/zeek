##! Various data structure definitions for use with Bro's communication system.

module Broker;

export {

	## A name used to identify this endpoint to peers.
	## .. bro:see:: Broker::connect Broker::listen
	const endpoint_name = "" &redef;

	## Change communication behavior.
	type EndpointFlags: record {
		## Whether to restrict message topics that can be published to peers.
		auto_publish: bool &default = T;
		## Whether to restrict what message topics or data store identifiers
		## the local endpoint advertises to peers (e.g. subscribing to
		## events or making a master data store available).
		auto_advertise: bool &default = T;
	};

	## Fine-grained tuning of communication behavior for a particular message.
	type SendFlags: record {
		## Send the message to the local endpoint.
		self: bool &default = F;
		## Send the message to peer endpoints that advertise interest in
		## the topic associated with the message.
		peers: bool &default = T;
		## Send the message to peer endpoints even if they don't advertise
		## interest in the topic associated with the message.
		unsolicited: bool &default = F;
	};

	## Opaque communication data.
	type Data: record {
		d: opaque of Broker::Data &optional;
	};

	## Opaque communication data.
	type DataVector: vector of Broker::Data;

	## Opaque event communication data.
	type EventArgs: record {
		## The name of the event.  Not set if invalid event or arguments.
		name: string &optional;
		## The arguments to the event.
		args: DataVector;
	};

	## Opaque communication data used as a convenient way to wrap key-value
	## pairs that comprise table entries.
	type TableItem : record {
		key: Broker::Data;
		val: Broker::Data;
	};
}
