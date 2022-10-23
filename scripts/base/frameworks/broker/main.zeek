##! The Broker-based communication API and its various options.

module Broker;

export {
	## Default port for native Broker communication. Where not specified
	## otherwise, this is the port to connect to and listen on.
	const default_port = 9999/tcp &redef;

	## Default port for Broker WebSocket communication. Where not specified
	## otherwise, this is the port to connect to and listen on for
	## WebSocket connections.
	##
	## See the Broker documentation for a specification of the message
	## format over WebSocket connections.
	const default_port_websocket = 9997/tcp &redef;

	## Default interval to retry listening on a port if it's currently in
	## use already.  Use of the ZEEK_DEFAULT_LISTEN_RETRY environment variable
	## (set as a number of seconds) will override this option and also
	## any values given to :zeek:see:`Broker::listen`.
	const default_listen_retry = 30sec &redef;

	## Default address on which to listen.
	##
	## .. zeek:see:: Broker::listen
	const default_listen_address = getenv("ZEEK_DEFAULT_LISTEN_ADDRESS") &redef;

	## Default address on which to listen for WebSocket connections.
	##
	## .. zeek:see:: Broker::listen_websocket
	const default_listen_address_websocket = getenv("ZEEK_DEFAULT_LISTEN_ADDRESS") &redef;

	## Default interval to retry connecting to a peer if it cannot be made to
	## work initially, or if it ever becomes disconnected.  Use of the
	## ZEEK_DEFAULT_CONNECT_RETRY environment variable (set as number of
	## seconds) will override this option and also any values given to
	## :zeek:see:`Broker::peer`.
	const default_connect_retry = 30sec &redef;

	## If true, do not use SSL for network connections. By default, SSL will
	## even be used if no certificates / CAs have been configured. In that case
	## (which is the default) the communication will be encrypted, but not
	## authenticated.
	const disable_ssl = F &redef;

	## Path to a file containing concatenated trusted certificates
	## in PEM format. If set, Zeek will require valid certificates for
	## all peers.
	const ssl_cafile = "" &redef;

	## Path to an OpenSSL-style directory of trusted certificates.
	## If set, Zeek will require valid certificates for
	## all peers.
	const ssl_capath = "" &redef;

	## Path to a file containing a X.509 certificate for this
	## node in PEM format. If set, Zeek will require valid certificates for
	## all peers.
	const ssl_certificate = "" &redef;

	## Passphrase to decrypt the private key specified by
	## :zeek:see:`Broker::ssl_keyfile`. If set, Zeek will require valid
	## certificates for all peers.
	const ssl_passphrase = "" &redef;

	## Path to the file containing the private key for this node's
	## certificate. If set, Zeek will require valid certificates for
	## all peers.
	const ssl_keyfile = "" &redef;

	## The number of buffered messages at the Broker/CAF layer after which
	## a subscriber considers themselves congested (i.e. tune the congestion
	## control mechanisms).
	const congestion_queue_size = 200 &redef;

	## The max number of log entries per log stream to batch together when
	## sending log messages to a remote logger.
	const log_batch_size = 400 &redef;

	## Max time to buffer log messages before sending the current set out as a
	## batch.
	const log_batch_interval = 1sec &redef;

	## Max number of threads to use for Broker/CAF functionality.  The
	## ZEEK_BROKER_MAX_THREADS environment variable overrides this setting.
	const max_threads = 1 &redef;

	## The CAF scheduling policy to use.  Available options are "sharing" and
	## "stealing".  The "sharing" policy uses a single, global work queue along
	## with mutex and condition variable used for accessing it, which may be
	## better for cases that don't require much concurrency or need lower power
	## consumption.  The "stealing" policy uses multiple work queues protected
	## by spinlocks, which may be better for use-cases that have more
	## concurrency needs.  E.g. may be worth testing the "stealing" policy
	## along with dedicating more threads if a lot of data store processing is
	## required.
	const scheduler_policy = "sharing" &redef;

	## Interval of time for under-utilized Broker/CAF threads to sleep
	## when in "moderate" mode.  Only used for the "stealing" scheduler policy.
	const moderate_sleep = 16 msec &redef;

	## Interval of time for under-utilized Broker/CAF threads to sleep
	## when in "relaxed" mode.  Only used for the "stealing" scheduler policy.
	const relaxed_sleep = 64 msec &redef;

	## Number of work-stealing polling attempts for Broker/CAF threads
	## in "aggressive" mode.  Only used for the "stealing" scheduler policy.
	const aggressive_polls = 5 &redef;

	## Number of work-stealing polling attempts for Broker/CAF threads
	## in "moderate" mode.  Only used for the "stealing" scheduler policy.
	const moderate_polls = 5 &redef;

	## Frequency of work-stealing polling attempts for Broker/CAF threads
	## in "aggressive" mode.  Only used for the "stealing" scheduler policy.
	const aggressive_interval = 4 &redef;

	## Frequency of work-stealing polling attempts for Broker/CAF threads
	## in "moderate" mode.  Only used for the "stealing" scheduler policy.
	const moderate_interval = 2 &redef;

	## Frequency of work-stealing polling attempts for Broker/CAF threads
	## in "relaxed" mode.  Only used for the "stealing" scheduler policy.
	const relaxed_interval = 1 &redef;

	## Forward all received messages to subscribing peers.
	const forward_messages = F &redef;

	## Whether calling :zeek:see:`Broker::peer` will register the Broker
	## system as an I/O source that will block the process from shutting
	## down.  For example, set this to false when you are reading pcaps,
	## but also want to initiate a Broker peering and still shutdown after
	## done reading the pcap.
	option peer_counts_as_iosource = T;

	## Port for Broker's metric exporter. Setting this to a valid TCP port causes
	## Broker to make metrics available to Prometheus scrapers via HTTP. Zeek
	## overrides any value provided in zeek_init or earlier at startup if the
	## environment variable BROKER_METRICS_PORT is defined.
	const metrics_port = 0/unknown &redef;

	## Frequency for publishing scraped metrics to the target topic. Zeek
	## overrides any value provided in zeek_init or earlier at startup if the
	## environment variable BROKER_METRICS_EXPORT_INTERVAL is defined.
	option metrics_export_interval = 1 sec;

	## Target topic for the metrics. Setting a non-empty string starts the
	## periodic publishing of local metrics. Zeek overrides any value provided in
	## zeek_init or earlier at startup if the environment variable
	## BROKER_METRICS_EXPORT_TOPIC is defined.
	option metrics_export_topic = "";

	## Topics for the Prometheus exporter for collecting metrics from other
	## peers in the network and including them in the output. Has no effect when
	## not exporting the metrics to Prometheus.
	##
	## Zeek overrides any value provided in zeek_init or earlier at startup if
	## the environment variable BROKER_METRICS_IMPORT_TOPICS is defined.
	option metrics_import_topics: vector of string = vector();

	## ID for the metrics exporter. When setting a target topic for the
	## exporter, Broker sets this option to the suffix of the new topic *unless*
	## the ID is a non-empty string. Since setting a topic starts the periodic
	## publishing of events, we recommend setting the ID always first or avoid
	## setting it at all if the topic suffix serves as a good-enough ID. Zeek
	## overrides any value provided in zeek_init or earlier at startup if the
	## environment variable BROKER_METRICS_ENDPOINT_NAME is defined.
	option metrics_export_endpoint_name = "";

	## Selects prefixes from the local metrics. Only metrics with prefixes
	## listed in this variable are included when publishing local metrics.
	## Setting an empty vector selects *all* metrics.
	option metrics_export_prefixes: vector of string = vector();

	## The default topic prefix where logs will be published.  The log's stream
	## id is appended when writing to a particular stream.
	const default_log_topic_prefix = "zeek/logs/" &redef;

	## The default implementation for :zeek:see:`Broker::log_topic`.
	function default_log_topic(id: Log::ID, path: string): string
		{
		return default_log_topic_prefix + cat(id);
		}

	## A function that will be called for each log entry to determine what
	## broker topic string will be used for sending it to peers.  The
	## default implementation will return a value based on
	## :zeek:see:`Broker::default_log_topic_prefix`.
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
		## A peering request timed out.
		PEER_TIMEOUT = 5,
		## Master with given name already exists.
		MASTER_EXISTS = 6,
		## Master with given name does not exist.
		NO_SUCH_MASTER = 7,
		## The given data store key does not exist.
		NO_SUCH_KEY = 8,
		## The store operation timed out.
		REQUEST_TIMEOUT = 9,
		## The operation expected a different type than provided.
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

	## Listen for remote connections using the native Broker protocol.
	##
	## a: an address string on which to accept connections, e.g.
	##    "127.0.0.1".  An empty string refers to INADDR_ANY.
	##
	## p: the TCP port to listen on. The value 0 means that the OS should choose
	##    the next available free port.
	##
	## retry: If non-zero, retries listening in regular intervals if the port cannot be
	##        acquired immediately. 0 disables retries.  If the
	##        ZEEK_DEFAULT_LISTEN_RETRY environment variable is set (as number
	##        of seconds), it overrides any value given here.
	##
	## Returns: the bound port or 0/? on failure.
	##
	## .. zeek:see:: Broker::status
	global listen: function(a: string &default = default_listen_address,
	                        p: port &default = default_port,
	                        retry: interval &default = default_listen_retry): port;

	## Listen for remote connections using WebSocket.
	##
	## a: an address string on which to accept connections, e.g.
	##    "127.0.0.1".  An empty string refers to INADDR_ANY.
	##
	## p: the TCP port to listen on. The value 0 means that the OS should choose
	##    the next available free port.
	##
	## retry: If non-zero, retries listening in regular intervals if the port cannot be
	##        acquired immediately. 0 disables retries.  If the
	##        ZEEK_DEFAULT_LISTEN_RETRY environment variable is set (as number
	##        of seconds), it overrides any value given here.
	##
	## Returns: the bound port or 0/? on failure.
	##
	## .. zeek:see:: Broker::status
	global listen_websocket: function(a: string &default = default_listen_address_websocket,
	                                  p: port &default = default_port_websocket,
	                                  retry: interval &default = default_listen_retry): port;

	## Initiate a remote connection.
	##
	## a: an address to connect to, e.g. "localhost" or "127.0.0.1".
	##
	## p: the TCP port on which the remote side is listening.
	##
	## retry: an interval at which to retry establishing the
	##        connection with the remote peer if it cannot be made initially, or
	##        if it ever becomes disconnected.  If the
	##        ZEEK_DEFAULT_CONNECT_RETRY environment variable is set (as number
	##        of seconds), it overrides any value given here.
	##
	## Returns: true if it's possible to try connecting with the peer and
	##          it's a new peer. The actual connection may not be established
	##          until a later point in time.
	##
	## .. zeek:see:: Broker::status
	global peer: function(a: string, p: port &default=default_port,
	                      retry: interval &default=default_connect_retry): bool;

	## Remove a remote connection.
	##
	## Note that this does not terminate the connection to the peer, it
	## just means that we won't exchange any further information with it
	## unless peering resumes later.
	##
	## a: the address used in previous successful call to :zeek:see:`Broker::peer`.
	##
	## p: the port used in previous successful call to :zeek:see:`Broker::peer`.
	##
	## Returns: true if the arguments match a previously successful call to
	##          :zeek:see:`Broker::peer`.
	##
	## TODO: We do not have a function yet to terminate a connection.
	global unpeer: function(a: string, p: port): bool;

	## Get a list of all peer connections.
	##
	## Returns: a list of all peer connections.
	global peers: function(): vector of PeerInfo;

	## Get a unique identifier for the local broker endpoint.
	##
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
	## prefix.  Note that subscriptions may not be altered immediately after
	## calling (except during :zeek:see:`zeek_init`).
	##
	## topic_prefix: a prefix to match against remote message topics.
	##               e.g. an empty prefix matches everything and "a" matches
	##               "alice" and "amy" but not "bob".
	##
	## Returns: true if it's a new event subscription and it is now registered.
	global subscribe: function(topic_prefix: string): bool;

	## Unregister interest in all peer event messages that use a topic prefix.
	## Note that subscriptions may not be altered immediately after calling
	## (except during :zeek:see:`zeek_init`).
	##
	## topic_prefix: a prefix previously supplied to a successful call to
	##               :zeek:see:`Broker::subscribe` or :zeek:see:`Broker::forward`.
	##
	## Returns: true if interest in the topic prefix is no longer advertised.
	global unsubscribe: function(topic_prefix: string): bool;

	## Register a topic prefix subscription for events that should only be
	## forwarded to any subscribing peers and not raise any event handlers
	## on the receiving/forwarding node.  i.e. it's the same as
	## :zeek:see:`Broker::subscribe` except matching events are not raised
	## on the receiver, just forwarded.  Use :zeek:see:`Broker::unsubscribe`
	## with the same argument to undo this operation.
	##
	## topic_prefix: a prefix to match against remote message topics.
	##               e.g. an empty prefix matches everything and "a" matches
	##               "alice" and "amy" but not "bob".
	##
	## Returns: true if a new event forwarding/subscription is now registered.
	global forward: function(topic_prefix: string): bool;

	## Automatically send an event to any interested peers whenever it is
	## locally dispatched. (For example, using "event my_event(...);" in a
	## script.)
	##
	## topic: a topic string associated with the event message.
	##        Peers advertise interest by registering a subscription to some
	##        prefix of this topic name.
	##
	## ev: a Zeek event value.
	##
	## Returns: true if automatic event sending is now enabled.
	global auto_publish: function(topic: string, ev: any): bool;

	## Stop automatically sending an event to peers upon local dispatch.
	##
	## topic: a topic originally given to :zeek:see:`Broker::auto_publish`.
	##
	## ev: an event originally given to :zeek:see:`Broker::auto_publish`.
	##
	## Returns: true if automatic events will not occur for the topic/event
	##          pair.
	global auto_unpublish: function(topic: string, ev: any): bool;
}

@load base/bif/comm.bif
@load base/bif/messaging.bif

module Broker;

event Broker::log_flush() &priority=10
	{
	Broker::flush_logs();
	schedule Broker::log_batch_interval { Broker::log_flush() };
	}

function update_metrics_export_interval(id: string, val: interval): interval
	{
	Broker::__set_metrics_export_interval(val);
	return val;
	}

function update_metrics_export_topic(id: string, val: string): string
	{
	Broker::__set_metrics_export_topic(val);
	return val;
	}

function update_metrics_import_topics(id: string, topics: vector of string): vector of string
	{
	Broker::__set_metrics_import_topics(topics);
	return topics;
	}

function update_metrics_export_endpoint_name(id: string, val: string): string
	{
	Broker::__set_metrics_export_endpoint_name(val);
	return val;
	}

function update_metrics_export_prefixes(id: string, filter: vector of string): vector of string
	{
	Broker::__set_metrics_export_prefixes(filter);
	return filter;
	}

event zeek_init()
	{
	schedule Broker::log_batch_interval { Broker::log_flush() };
	# interval
	update_metrics_export_interval("Broker::metrics_export_interval",
	                               Broker::metrics_export_interval);
	Option::set_change_handler("Broker::metrics_export_interval",
	                           update_metrics_export_interval);
	# topic
	update_metrics_export_topic("Broker::metrics_export_topic",
	                            Broker::metrics_export_topic);
	Option::set_change_handler("Broker::metrics_export_topic",
	                           update_metrics_export_topic);
	# import topics
	update_metrics_import_topics("Broker::metrics_import_topics",
	                             Broker::metrics_import_topics);
	Option::set_change_handler("Broker::metrics_import_topics",
	                           update_metrics_import_topics);
	# endpoint name
	update_metrics_export_endpoint_name("Broker::metrics_export_endpoint_name",
	                                    Broker::metrics_export_endpoint_name);
	Option::set_change_handler("Broker::metrics_export_endpoint_name",
	                           update_metrics_export_endpoint_name);
	# prefixes
	update_metrics_export_prefixes("Broker::metrics_export_prefixes",
	                               Broker::metrics_export_prefixes);
	Option::set_change_handler("Broker::metrics_export_prefixes",
	                           update_metrics_export_prefixes);
	}

event retry_listen(a: string, p: port, retry: interval)
	{
	listen(a, p, retry);
	}

function listen(a: string, p: port, retry: interval): port
	{
	local bound = __listen(a, p, Broker::NATIVE);

	if ( bound == 0/tcp )
		{
		local e = getenv("ZEEK_DEFAULT_LISTEN_RETRY");

		if ( e != "" )
			retry = double_to_interval(to_double(e));

		if ( retry != 0secs )
			schedule retry { retry_listen(a, p, retry) };
		}

	return bound;
	}

event retry_listen_websocket(a: string, p: port, retry: interval)
	{
	listen_websocket(a, p, retry);
	}

function listen_websocket(a: string, p: port, retry: interval): port
	{
	local bound = __listen(a, p, Broker::WEBSOCKET);

	if ( bound == 0/tcp )
		{
		local e = getenv("ZEEK_DEFAULT_LISTEN_RETRY");

		if ( e != "" )
			retry = double_to_interval(to_double(e));

		if ( retry != 0secs )
			schedule retry { retry_listen_websocket(a, p, retry) };
		}

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

function forward(topic_prefix: string): bool
	{
	return __forward(topic_prefix);
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
