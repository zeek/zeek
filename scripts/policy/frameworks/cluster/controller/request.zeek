##! This module implements a request state abstraction that both cluster
##! controller and agent use to tie responses to received request events and be
##! able to time-out such requests.

@load ./types
@load ./config

module ClusterController::Request;

export {
	## Request records track each request's state.
	type Request: record {
		## Each request has a hopfully unique ID provided by the requester.
		id: string;

		## For requests that result based upon another request (such as when
		## the controller sends requests to agents based on a request it
		## received by the client), this specifies that original, "parent"
		## request.
		parent_id: string &optional;
	};

	# API-specific state. XXX we may be able to generalize after this has
	# settled a bit more. It would also be nice to move request-specific
	# state out of this module -- we could for example redef Request in
	# main.zeek as needed.

	# State specific to the set_configuration request/response events
	type SetConfigurationState: record {
		config: ClusterController::Types::Configuration;
		requests: set[string] &default=set();
	};

	# State specific to supervisor interactions
	type SupervisorState: record {
		node: string;
	};

	# State for testing events
	type TestState: record {
	};

	# The redef is a workaround so we can use the Request type
	# while it is still being defined.
	redef record Request += {
		results: ClusterController::Types::ResultVec &default=vector();
		finished: bool &default=F;

		set_configuration_state: SetConfigurationState &optional;
		supervisor_state: SupervisorState &optional;
		test_state: TestState &optional;
	};

	## A token request that serves as a null/nonexistant request.
	global null_req = Request($id="", $finished=T);

	## This function establishes request state.
	##
	## reqid: the identifier to use for the request.
	##
	global create: function(reqid: string &default=unique_id("")): Request;

	## This function looks up the request for a given request ID and returns
	## it. When no such request exists, returns ClusterController::Request::null_req.
	##
	## reqid: the ID of the request state to retrieve.
	##
	global lookup: function(reqid: string): Request;

	## This function marks a request as complete and causes Zeek to release
	## its internal state. When the request does not exist, this does
	## nothing.
	##
	## reqid: the ID of the request state to releaase.
	##
	global finish: function(reqid: string): bool;

	## This event fires when a request times out (as per the
	## ClusterController::request_timeout) before it has been finished via
	## ClusterController::Request::finish().
	##
	## req: the request state that is expiring.
	##
	global request_expired: event(req: Request);

	## This function is a helper predicate to indicate whether a given
	## request is null.
	##
	## request: a Request record to check.
	##
	## Returns: T if the given request matches the null_req instance, F otherwise.
	##
	global is_null: function(request: Request): bool;

	## For troubleshooting, this function renders a request record to a string.
	##
	## request: the request to render.
	##
	global to_string: function(request: Request): string;
}

function requests_expire_func(reqs: table[string] of Request, reqid: string): interval
	{
	event ClusterController::Request::request_expired(reqs[reqid]);
	return 0secs;
	}

# This is the global request-tracking table. The table maps from request ID
# strings to corresponding Request records. Entries time out after the
# ClusterController::request_timeout interval. Upon expiration, a
# request_expired event triggers that conveys the request state.
global g_requests: table[string] of Request
    &create_expire=ClusterController::request_timeout
    &expire_func=requests_expire_func;

function create(reqid: string): Request
	{
	local ret = Request($id=reqid);
	g_requests[reqid] = ret;
	return ret;
	}

function lookup(reqid: string): Request
	{
	if ( reqid in g_requests )
		return g_requests[reqid];

	return null_req;
	}

function finish(reqid: string): bool
	{
	if ( reqid !in g_requests )
		return F;

	local req = g_requests[reqid];
	delete g_requests[reqid];

	req$finished = T;

	return T;
	}

function is_null(request: Request): bool
	{
	if ( request$id == "" )
		return T;

	return F;
	}

function to_string(request: Request): string
	{
	local results: string_vec;
	local res: ClusterController::Types::Result;
	local parent_id = "";

	if ( request?$parent_id )
		parent_id = fmt(" (via %s)", request$parent_id);

	for ( idx in request$results )
		{
		res = request$results[idx];
		results[|results|] = ClusterController::Types::result_to_string(res);
		}

	return fmt("[request %s%s %s, results: %s]", request$id, parent_id,
	           request$finished ? "finished" : "pending",
	           join_string_vec(results, ","));
	}
