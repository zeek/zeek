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

	## A name used to identify this endpoint to peers.
	##
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

	## Enable use of communication.
	##
	## flags: used to tune the local Broker endpoint behavior.
	##
	## Returns: true if communication is successfully initialized.
	global enable: function(flags: EndpointFlags &default = EndpointFlags()): bool;

	## Changes endpoint flags originally supplied to :bro:see:`Broker::enable`.
	##
	## flags: the new endpoint behavior flags to use.
	##
	## Returns: true if flags were changed.
	global set_endpoint_flags: function(flags: EndpointFlags &default = EndpointFlags()): bool;

	## Allow sending messages to peers if associated with the given topic.
	## This has no effect if auto publication behavior is enabled via the flags
	## supplied to :bro:see:`Broker::enable` or :bro:see:`Broker::set_endpoint_flags`.
	##
	## topic: a topic to allow messages to be published under.
	##
	## Returns: true if successful.
	global publish_topic: function(topic: string): bool;

	## Disallow sending messages to peers if associated with the given topic.
	## This has no effect if auto publication behavior is enabled via the flags
	## supplied to :bro:see:`Broker::enable` or :bro:see:`Broker::set_endpoint_flags`.
	##
	## topic: a topic to disallow messages to be published under.
	##
	## Returns: true if successful.
	global unpublish_topic: function(topic: string): bool;

	## Listen for remote connections.
	##
	## p: the TCP port to listen on.
	##
	## a: an address string on which to accept connections, e.g.
	##    "127.0.0.1".  An empty string refers to @p INADDR_ANY.
	##
	## reuse: equivalent to behavior of SO_REUSEADDR.
	##
	## Returns: true if the local endpoint is now listening for connections.
	##
	## .. bro:see:: Broker::incoming_connection_established
	global listen: function(p: port, a: string &default = "", reuse: bool &default = T): bool;

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
	##          it's a new peer.  The actual connection may not be established
	##          until a later point in time.
	##
	## .. bro:see:: Broker::outgoing_connection_established
	global connect: function(a: string, p: port, retry: interval): bool;

	## Remove a remote connection.
	##
	## a: the address used in previous successful call to :bro:see:`Broker::connect`.
	##
	## p: the port used in previous successful call to :bro:see:`Broker::connect`.
	##
	## Returns: true if the arguments match a previously successful call to
	##          :bro:see:`Broker::connect`.
	global disconnect: function(a: string, p: port): bool;

	## Print a simple message to any interested peers.  The receiver can use
	## :bro:see:`Broker::print_handler` to handle messages.
	##
	## topic: a topic associated with the printed message.
	##
	## msg: the print message to send to peers.
	##
	## flags: tune the behavior of how the message is sent.
	##
	## Returns: true if the message is sent.
	global send_print: function(topic: string, msg: string, flags: SendFlags &default = SendFlags()): bool;

	## Register interest in all peer print messages that use a certain topic
	## prefix. Use :bro:see:`Broker::print_handler` to handle received
	## messages.
	##
	## topic_prefix: a prefix to match against remote message topics.
	##               e.g. an empty prefix matches everything and "a" matches
	##               "alice" and "amy" but not "bob".
	##
	## Returns: true if it's a new print subscription and it is now registered.
	global subscribe_to_prints: function(topic_prefix: string): bool;

	## Unregister interest in all peer print messages that use a topic prefix.
	##
	## topic_prefix: a prefix previously supplied to a successful call to
	##               :bro:see:`Broker::subscribe_to_prints`.
	##
	## Returns: true if interest in the topic prefix is no longer advertised.
	global unsubscribe_to_prints: function(topic_prefix: string): bool;

	## Send an event to any interested peers.
	##
	## topic: a topic associated with the event message.
	##
	## args: event arguments as made by :bro:see:`Broker::event_args`.
	##
	## flags: tune the behavior of how the message is sent.
	##
	## Returns: true if the message is sent.
	global send_event: function(topic: string, args: EventArgs, flags: SendFlags &default = SendFlags()): bool;

	## Automatically send an event to any interested peers whenever it is
	## locally dispatched (e.g. using "event my_event(...);" in a script).
	##
	## topic: a topic string associated with the event message.
	##        Peers advertise interest by registering a subscription to some
	##        prefix of this topic name.
	##
	## ev: a Bro event value.
	##
	## flags: tune the behavior of how the message is sent.
	##
	## Returns: true if automatic event sending is now enabled.
	global auto_event: function(topic: string, ev: any, flags: SendFlags &default = SendFlags()): bool;

	## Stop automatically sending an event to peers upon local dispatch.
	##
	## topic: a topic originally given to :bro:see:`Broker::auto_event`.
	##
	## ev: an event originally given to :bro:see:`Broker::auto_event`.
	##
	## Returns: true if automatic events will not occur for the topic/event
	##          pair.
	global auto_event_stop: function(topic: string, ev: any): bool;

	## Register interest in all peer event messages that use a certain topic
	## prefix.
	##
	## topic_prefix: a prefix to match against remote message topics.
	##               e.g. an empty prefix matches everything and "a" matches
	##               "alice" and "amy" but not "bob".
	##
	## Returns: true if it's a new event subscription and it is now registered.
	global subscribe_to_events: function(topic_prefix: string): bool;

	## Unregister interest in all peer event messages that use a topic prefix.
	##
	## topic_prefix: a prefix previously supplied to a successful call to
	##               :bro:see:`Broker::subscribe_to_events`.
	##
	## Returns: true if interest in the topic prefix is no longer advertised.
	global unsubscribe_to_events: function(topic_prefix: string): bool;

	## Enable remote logs for a given log stream.
	##
	## id: the log stream to enable remote logs for.
	##
	## flags: tune the behavior of how log entry messages are sent.
	##
	## Returns: true if remote logs are enabled for the stream.
	global enable_remote_logs: function(id: Log::ID, flags: SendFlags &default = SendFlags()): bool;

	## Disable remote logs for a given log stream.
	##
	## id: the log stream to disable remote logs for.
	##
	## Returns: true if remote logs are disabled for the stream.
	global disable_remote_logs: function(id: Log::ID): bool;

	## Check if remote logs are enabled for a given log stream.
	##
	## id: the log stream to check.
	##
	## Returns: true if remote logs are enabled for the given stream.
	global remote_logs_enabled: function(id: Log::ID): bool;

	## Register interest in all peer log messages that use a certain topic
	## prefix. Logs are implicitly sent with topic "bro/log/<stream-name>" and
	## the receiving side processes them through the logging framework as usual.
	##
	## topic_prefix: a prefix to match against remote message topics.
	##               e.g. an empty prefix matches everything and "a" matches
	##               "alice" and "amy" but not "bob".
	##
	## Returns: true if it's a new log subscription and it is now registered.
	global subscribe_to_logs: function(topic_prefix: string): bool;

	## Unregister interest in all peer log messages that use a topic prefix.
	## Logs are implicitly sent with topic "bro/log/<stream-name>" and the
	## receiving side processes them through the logging framework as usual.
	##
	## topic_prefix: a prefix previously supplied to a successful call to
	##               :bro:see:`Broker::subscribe_to_logs`.
	##
	## Returns: true if interest in the topic prefix is no longer advertised.
	global unsubscribe_to_logs: function(topic_prefix: string): bool;

}

@load base/bif/comm.bif
@load base/bif/messaging.bif

module Broker;

@ifdef ( Broker::__enable )

function enable(flags: EndpointFlags &default = EndpointFlags()) : bool
    {
    return __enable(flags);
    }

function set_endpoint_flags(flags: EndpointFlags &default = EndpointFlags()): bool
    {
    return __set_endpoint_flags(flags);
    }

function publish_topic(topic: string): bool
    {
    return __publish_topic(topic);
    }

function unpublish_topic(topic: string): bool
    {
    return __unpublish_topic(topic);
    }

function listen(p: port, a: string &default = "", reuse: bool &default = T): bool
    {
    return __listen(p, a, reuse);
    }

function connect(a: string, p: port, retry: interval): bool
    {
    return __connect(a, p, retry);
    }

function disconnect(a: string, p: port): bool
    {
    return __disconnect(a, p);
    }

function send_print(topic: string, msg: string, flags: SendFlags &default = SendFlags()): bool
    {
    return __send_print(topic, msg, flags);
    }

function subscribe_to_prints(topic_prefix: string): bool
    {
    return __subscribe_to_prints(topic_prefix);
    }

function unsubscribe_to_prints(topic_prefix: string): bool
    {
    return __unsubscribe_to_prints(topic_prefix);
    }

function send_event(topic: string, args: EventArgs, flags: SendFlags &default = SendFlags()): bool
    {
    return __event(topic, args, flags);
    }

function auto_event(topic: string, ev: any, flags: SendFlags &default = SendFlags()): bool
    {
    return __auto_event(topic, ev, flags);
    }

function auto_event_stop(topic: string, ev: any): bool
    {
    return __auto_event_stop(topic, ev);
    }

function subscribe_to_events(topic_prefix: string): bool
    {
    return __subscribe_to_events(topic_prefix);
    }

function unsubscribe_to_events(topic_prefix: string): bool
    {
    return __unsubscribe_to_events(topic_prefix);
    }

function enable_remote_logs(id: Log::ID, flags: SendFlags &default = SendFlags()): bool
    {
    return __enable_remote_logs(id, flags);
    }

function disable_remote_logs(id: Log::ID): bool
    {
    return __disable_remote_logs(id);
    }

function remote_logs_enabled(id: Log::ID): bool
    {
    return __remote_logs_enabled(id);
    }

function subscribe_to_logs(topic_prefix: string): bool
    {
    return __subscribe_to_logs(topic_prefix);
    }

function unsubscribe_to_logs(topic_prefix: string): bool
    {
    return __unsubscribe_to_logs(topic_prefix);
    }

@endif
