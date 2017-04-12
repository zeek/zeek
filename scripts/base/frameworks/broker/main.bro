##! Various data structure definitions for use with Bro's communication system.

module Log;

export {
    type Log::ID: enum {
        ## Dummy place-holder.
        UNKNOWN
    };
}

module Broker;

export {

	## The available configuration options when enabling Broker.
	type Options: record {
		## A name used to identify this endpoint to peers.
		endpoint_name: string &default = "";
		## Whether this Broker instance relays messages not destined to itself.
		routable: bool &default = T;
	};

	## TODO: fill in the remaining error codes.
	type ErrorCode: enum {
		UNSPECIFIED,
	};

	type NetworkInfo : record {
		## The IP address where the endpoint listens.
		address: addr;
		## The port where the endpoint is bound to.
		bound_port: port;
  };

	type EndpointInfo: record {
		## A unique identifier of the node.
		id: string;
		## Network-level information.
		network: NetworkInfo &optional;
	};

	## Opaque communication data.
	type Data: record {
		data: opaque of Broker::Data &optional;
	};

	## Opaque communication data sequence.
	type DataVector: vector of Broker::Data;

	## Opaque event communication data.
	type Event: record {
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

	## Enables use of communication.
	##
	## options: used to tune the local Broker endpoint behavior.
	##
	## Returns: true if communication is successfully initialized.
	global enable: function(options: Options &default = Options()): bool;

	## Listen for remote connections.
	##
	## p: the TCP port to listen on. The value 0 means that the OS should choose
	##    the next available free port.
	##
	## a: an address string on which to accept connections, e.g.
	##    "127.0.0.1".  An empty string refers to @p INADDR_ANY.
	##
	## Returns: the bound port or 0/? on failure.
	##
	## .. bro:see:: Broker::status
	global listen: function(p: port &default = 0/tcp, a: string &default = ""): port;

	## Initiate a remote connection.
	##
	## a: an address to connect to, e.g. "localhost" or "127.0.0.1".
	##
	## p: the TCP port on which the remote side is listening.
	##
	## retry: an interval at which to retry establishing the
	##        connection with the remote peer if it cannot be made initially, or
	##        if it ever becomes disconnected.
	##
	## Returns: true if it's possible to try connecting with the peer and
	##          it's a new peer. The actual connection may not be established
	##          until a later point in time.
	##
	## .. bro:see:: Broker::status
	# TODO: re-implement retry
	global peer: function(a: string, p: port): bool;

	## Remove a remote connection.
	##
	## a: the address used in previous successful call to :bro:see:`Broker::peer`.
	##
	## p: the port used in previous successful call to :bro:see:`Broker::peer`.
	##
	## Returns: true if the arguments match a previously successful call to
	##          :bro:see:`Broker::peer`.
	global unpeer: function(a: string, p: port): bool;

	## Publishes an event at a given topic.
	##
	## topic: a topic associated with the event message.
	##
	## ev: The event arguments as made by :bro:see:`Broker::make_event`.
	##
	## Returns: true if the message is sent.
	global publish: function(topic: string, args: Event): bool;

	## Register interest in all peer event messages that use a certain topic
	## prefix.
	##
	## topic_prefix: a prefix to match against remote message topics.
	##               e.g. an empty prefix matches everything and "a" matches
	##               "alice" and "amy" but not "bob".
	##
	## Returns: true if it's a new event subscription and it is now registered.
	global subscribe: function(topic_prefix: string): bool;

	## Unregister interest in all peer event messages that use a topic prefix.
	##
	## topic_prefix: a prefix previously supplied to a successful call to
	##               :bro:see:`Broker::subscribe_to_events`.
	##
	## Returns: true if interest in the topic prefix is no longer advertised.
	global unsubscribe: function(topic_prefix: string): bool;

	## Automatically send an event to any interested peers whenever it is
	## locally dispatched (e.g. using "event my_event(...);" in a script).
	##
	## topic: a topic string associated with the event message.
	##        Peers advertise interest by registering a subscription to some
	##        prefix of this topic name.
	##
	## ev: a Bro event value.
	##
	## Returns: true if automatic event sending is now enabled.
	global auto_publish: function(topic: string, ev: any): bool;

	## Stop automatically sending an event to peers upon local dispatch.
	##
	## topic: a topic originally given to :bro:see:`Broker::auto_event`.
	##
	## ev: an event originally given to :bro:see:`Broker::auto_event`.
	##
	## Returns: true if automatic events will not occur for the topic/event
	##          pair.
	global auto_unpublish: function(topic: string, ev: any): bool;

	## Enable publishing logs for a given log stream.
	##
	## id: the log stream to enable publishing logs for.
	##
	## Returns: true if publishing logs are enabled for the stream.
	global auto_log: function(id: Log::ID): bool;

	## Disable publishing logs for a given log stream.
	##
	## id: the log stream to disable publishing logs for.
	##
	## Returns: true if publishing logs are disabled for the stream.
	global auto_unlog: function(id: Log::ID): bool;
}

@load base/bif/comm.bif
@load base/bif/messaging.bif

module Broker;

function enable(options: Options &default = Options()): bool
    {
    return __enable(options);
    }

function listen(p: port, a: string &default = ""): port
    {
    return __listen(p, a);
    }

function peer(a: string, p: port): bool
    {
    return __peer(a, p);
    }

function unpeer(a: string, p: port): bool
    {
    return __unpeer(a, p);
    }

function publish(topic: string, ev: Event): bool
    {
    return __publish(topic, ev);
    }

function subscribe(topic_prefix: string): bool
    {
    return __subscribe(topic_prefix);
    }

function unsubscribe(topic_prefix: string): bool
    {
    return __unsubscribe(topic_prefix);
    }

function auto_publish(topic: string, ev: any): bool
    {
    return __auto_publish(topic, ev);
    }

function auto_unpublish(topic: string, ev: any): bool
    {
    return __auto_unpublish(topic, ev);
    }

function auto_log(id: Log::ID): bool
    {
    return F; # TODO: implement this function.
    }

function auto_unlog(id: Log::ID): bool
    {
    return F; # TODO: implement this function.
    }
