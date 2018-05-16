##! The Broker-based communication API and its various options.

module Broker;

export {
	## Default port for Broker communication. Where not specified
	## otherwise, this is the port to connect to and listen on.
	const default_port = 9999/tcp &redef;

	## Default interval to retry listening on a port if it's currently in
	## use already.
	const default_listen_retry = 30sec &redef;

	## Default address on which to listen.
	##
	## .. bro:see:: Broker::listen
	const default_listen_address = "" &redef;

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
	## :bro:see:`Broker::ssl_keyfile`. If set, Bro will require valid
	## certificates for all peers.
	const ssl_passphrase = "" &redef;

	## Path to the file containing the private key for this node's
	## certificate. If set, Bro will require valid certificates for
	## all peers.
	const ssl_keyfile = "" &redef;

	## Forward all received messages to subscribing peers.
	const forward_messages = F &redef;

	## The default topic prefix where logs will be published.  The log's stream
	## id is appended when writing to a particular stream.
	const default_log_topic_prefix = "bro/logs/" &redef;

	## The default implementation for :bro:see:`Broker::log_topic`.
	function default_log_topic(id: Log::ID, path: string): string
		{
		return default_log_topic_prefix + cat(id);
		}

	## A function that will be called for each log entry to determine what
	## broker topic string will be used for sending it to peers.  The
	## default implementation will return a value based on
	## :bro:see:`Broker::default_log_topic_prefix`.
	##
	## id: the ID associated with the log stream entry that will be sent.
	##
	## path: the path to which the log stream entry will be output.
	##
	## Returns: a string representing the broker topic to which the log
	##          will be sent.
	const log_topic: function(id: Log::ID, path: string): string = default_log_topic &redef;

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
		## The storage backend failed to execute the operation.
		STALE_DATA = 13,
		## Catch-all for a CAF-level problem.
		CAF_ERROR = 100
	};

	## The possible states of a peer endpoint.
	type PeerStatus: enum {
		## The peering process is initiated.
		INITIALIZING,
		## Connection establishment in process.
		CONNECTING,
		## Connection established, peering pending.
		CONNECTED,
		## Successfully peered.
		PEERED,
		## Connection to remote peer lost.
		DISCONNECTED,
		## Reconnecting to peer after a lost connection.
		RECONNECTING,
	};

	type NetworkInfo: record {
		## The IP address or hostname where the endpoint listens.
		address: string &log;
		## The port where the endpoint is bound to.
		bound_port: port &log;
	};

	type EndpointInfo: record {
		## A unique identifier of the node.
		id: string;
		## Network-level information.
		network: NetworkInfo &optional;
	};

	type PeerInfo: record {
		peer: EndpointInfo;
		status: PeerStatus;
	};

	type PeerInfos: vector of PeerInfo;

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
	global listen: function(a: string &default = default_listen_address,
	                        p: port &default = default_port,
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

	## Returns: a list of all peer connections.
	global peers: function(): vector of PeerInfo;

	## Returns: a unique identifier for the local broker endpoint.
	global node_id: function(): string;

	## Sends all pending log messages to remote peers.  This normally
	## doesn't need to be used except for test cases that are time-sensitive.
	global flush_logs: function(): count;

	## Publishes the value of an identifier to a given topic.  The subscribers
	## will update their local value for that identifier on receipt.
	##
	## topic: a topic associated with the message.
	##
	## id: the identifier to publish.
	##
	## Returns: true if the message is sent.
	global publish_id: function(topic: string, id: string): bool;

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
	##               :bro:see:`Broker::subscribe`.
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
	## topic: a topic originally given to :bro:see:`Broker::auto_publish`.
	##
	## ev: an event originally given to :bro:see:`Broker::auto_publish`.
	##
	## Returns: true if automatic events will not occur for the topic/event
	##          pair.
	global auto_unpublish: function(topic: string, ev: any): bool;
}

@load base/bif/comm.bif
@load base/bif/messaging.bif

module Broker;

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

function peers(): vector of PeerInfo
	{
	return __peers();
	}

function node_id(): string
	{
	return __node_id();
	}

function flush_logs(): count
	{
	return __flush_logs();
	}

function publish_id(topic: string, id: string): bool
	{
	return __publish_id(topic, id);
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
