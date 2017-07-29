#! Various data structure definitions for use with Bro's communication system.

module Log;

export {
    type Log::ID: enum {
        ## Dummy place-holder.
        UNKNOWN
    };
}

module Broker;

export {
        ## Default port for Broker communication. Where not specified
        ## otherwise, this is the port to connect to and listen on.
        const default_port = 9999/tcp &redef;

        ## Default interval to retry listening on a port if it's currently in
        ## use already.
        const default_listen_retry = 30sec &redef;

        ## Default interval to retry connecting to a peer if it cannot be made to work
        ## initially, or if it ever becomes disconnected.
        const default_connect_retry = 30sec &redef;

        ## If false, do not use SSL for network connections. By default, SSL will even
        ## be used if no certificates / CAs have been configured. In that case
        ## (which is the default) the communication will be encrypted, but not
        ## authenticated.
        const disable_ssl = F &redef;

        ## Path to a file containing concatenated trusted certificates 
        ## in PEM format. If set, Bro will require valid certificates forx
        ## all peers.
	const ssl_cafile = "" &redef;

        ## Path to an OpenSSL-style directory of trusted certificates.
        ## If set, Bro will require valid certificates forx
        ## all peers.
        const ssl_capath = "" &redef;

        ## Path to a file containing a X.509 certificate for this
        ## node in PEM format. If set, Bro will require valid certificates for
        ## all peers.
        const ssl_certificate = "" &redef;

        ## Passphrase to decrypt the private key specified by
        ## :bro:see:`ssl_key`. If set, Bro will require valid certificates for
        ## all peers.
        const ssl_passphrase = "" &redef;

        ## Path to the file containing the private key for this node's
        ## certificate. If set, Bro will require valid certificates for
        ## all peers.
        const ssl_keyfile = "" &redef;

	## The available configuration options when enabling Broker.
	type Options: record {
		## Whether this Broker instance relays messages not destined to itself.
                ## By default, routing is disabled.
		routable: bool &default = F;
	        ## The topic prefix where to publish logs.
                log_topic: string &default = "bro/logs/";
	};

	type ErrorCode: enum {
		## The unspecified default error code.
		UNSPECIFIED = 1,
		## Version incompatibility.
		PEER_INCOMPATIBLE = 2,
		## Referenced peer does not exist.
		PEER_INVALID = 3,
		## Remote peer not listening.
		PEER_UNAVAILABLE = 4,
		## An peering request timed out.
	 	PEER_TIMEOUT = 5,
		## Master with given name already exist.
	 	MASTER_EXISTS = 6,
		## Master with given name does not exist.
	 	NO_SUCH_MASTER = 7,
		## The given data store key does not exist.
	 	NO_SUCH_KEY = 8,
		## The store operation timed out.
	 	REQUEST_TIMEOUT = 9,
		## The operation expected a different type than provided
	 	TYPE_CLASH = 10,
		## The data value cannot be used to carry out the desired operation.
		INVALID_DATA = 11,
		## The storage backend failed to execute the operation.
		BACKEND_FAILURE = 12,
		## Catch-all for a CAF-level problem.
	        CAF_ERROR = 100
	};

	type NetworkInfo: record {
		## The IP address where the endpoint listens.
		address: addr &log;
		## The port where the endpoint is bound to.
		bound_port: port &log;
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

	## Configures the local endpoint.
	##
	## options: Configures the local Broker endpoint behavior.
	##
	## Returns: true if configuration was successfully performed..
	global configure: function(options: Options &default = Options()): bool;

	## Listen for remote connections.
	##
	## a: an address string on which to accept connections, e.g.
	##    "127.0.0.1".  An empty string refers to @p INADDR_ANY.
        ##
	## p: the TCP port to listen on. The value 0 means that the OS should choose
	##    the next available free port.
	##
 	## retry: If non-zero, retries listening in regular intervals if the port cannot be
 	##        acquired immediately. 0 disables retries.
	##
	## Returns: the bound port or 0/? on failure.
	##
	## .. bro:see:: Broker::status
        global listen: function(a: string &default = "", p: port &default=default_port,
                                retry: interval &default = default_listen_retry): port;
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
        global peer: function(a: string, p: port &default=default_port,
			      retry: interval &default=default_connect_retry): bool;

	## Remove a remote connection.
        ##
        ## Note that this does not terminate the connection to the peer, it
        ## just means that we won't exchange any further information with it
        ## unless peering resumes later.
	##
	## a: the address used in previous successful call to :bro:see:`Broker::peer`.
	##
	## p: the port used in previous successful call to :bro:see:`Broker::peer`.
	##
	## Returns: true if the arguments match a previously successful call to
	##          :bro:see:`Broker::peer`.
        ##
        ## TODO: We do not have a function yet to terminate a connection.
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
}

@load base/bif/comm.bif
@load base/bif/messaging.bif

module Broker;

event bro_init() &priority=-10
	{
	configure(); # Configure with defaults.
	}

function configure(options: Options &default = Options()): bool
    {
    return __configure(options);
    }

event retry_listen(a: string, p: port, retry: interval)
    {
    listen(a, p, retry);
    }

function listen(a: string, p: port, retry: interval): port
    {
    local bound = __listen(a, p);

    if ( bound == 0/tcp && retry != 0secs )
	    schedule retry { retry_listen(a, p, retry) };

    return bound;
    }

function peer(a: string, p: port, retry: interval): bool
    {
    return __peer(a, p, retry);
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
