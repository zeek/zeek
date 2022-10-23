##! The Zeek process supervision (remote) control API.  This defines a Broker topic
##! prefix and events that can be used to control an external Zeek supervisor process.
##! This API was introduced in Zeek 3.1.0 and considered unstable until 4.0.0.
##! That is, it may change in various incompatible ways without warning or
##! deprecation until the stable 4.0.0 release.

@load base/frameworks/broker
@load ./api

module SupervisorControl;

export {
	## The Broker topic prefix to use when subscribing to Supervisor API
	## requests and when publishing Supervisor API responses.  If you are
	## publishing Supervisor requests, this is also the prefix string to use
	## for their topic names.
	const topic_prefix = "zeek/supervisor" &redef;

	## When enabled, the Supervisor will listen on the configured Broker
	## :zeek:see:`Broker::default_listen_address`.
	const enable_listen = F &redef;

	## Send a request to a remote Supervisor process to create a node.
	##
	## reqid: an arbitrary string that will be directly echoed in the response
	##
	## node: the desired configuration for the new supervised node process.
	global SupervisorControl::create_request: event(reqid: string, node: Supervisor::NodeConfig);

	## Handle a response from a Supervisor process that received
	## :zeek:see:`SupervisorControl::create_request`.
	##
	## reqid: an arbitrary string matching the value in the original request.
	##
	## result: the return value of the remote call to
	##         :zeek:see:`Supervisor::create`.
	global SupervisorControl::create_response: event(reqid: string, result: string);

	## Send a request to a remote Supervisor process to retrieve node status.
	##
	## reqid: an arbitrary string that will be directly echoed in the response
	##
	## node: the name of the node to get status of or empty string to mean "all
	##       nodes".
	global SupervisorControl::status_request: event(reqid: string, node: string);

	## Handle a response from a Supervisor process that received
	## :zeek:see:`SupervisorControl::status_request`.
	##
	## reqid: an arbitrary string matching the value in the original request.
	##
	## result: the return value of the remote call to
	##         :zeek:see:`Supervisor::status`.
	global SupervisorControl::status_response: event(reqid: string, result: Supervisor::Status);

	## Send a request to a remote Supervisor process to restart a node.
	##
	## reqid: an arbitrary string that will be directly echoed in the response
	##
	## node: the name of the node to restart or empty string to mean "all
	##       nodes".
	global SupervisorControl::restart_request: event(reqid: string, node: string);

	## Handle a response from a Supervisor process that received
	## :zeek:see:`SupervisorControl::restart_request`.
	##
	## reqid: an arbitrary string matching the value in the original request.
	##
	## result: the return value of the remote call to
	##         :zeek:see:`Supervisor::restart`.
	global SupervisorControl::restart_response: event(reqid: string, result: bool);

	## Send a request to a remote Supervisor process to destroy a node.
	##
	## reqid: an arbitrary string that will be directly echoed in the response
	##
	## node: the name of the node to destroy or empty string to mean "all
	##       nodes".
	global SupervisorControl::destroy_request: event(reqid: string, node: string);

	## Handle a response from a Supervisor process that received
	## :zeek:see:`SupervisorControl::destroy_request`.
	##
	## reqid: an arbitrary string matching the value in the original request.
	##
	## result: the return value of the remote call to
	##         :zeek:see:`Supervisor::destroy`.
	global SupervisorControl::destroy_response: event(reqid: string, result: bool);

	## Send a request to a remote Supervisor to stop and shutdown its
	## process tree.  There is no response to this message as the Supervisor
	## simply terminates on receipt.
	global SupervisorControl::stop_request: event();

	## A notification event the Supervisor generates when it receives a
	## status message update from the stem, indicating node has
	## (re-)started. This is the remote equivalent of
	## :zeek:see:`Supervisor::node_status`.
	##
	## node: the name of a previously created node via
	##       :zeek:see:`Supervisor::create` indicating to which
	##       child process the stdout line is associated.
	##
	## pid: the process ID the stem reported for this node.
	global SupervisorControl::node_status: event(node: string, pid: count);
}
