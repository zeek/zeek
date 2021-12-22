@load ./types
@load ./config

module ClusterController::Request;

export {
	type Request: record {
		id: string;
		parent_id: string &optional;
	};

	# API-specific state. XXX we may be able to generalize after this has
	# settled a bit more. It would also be nice to move request-specific
	# state out of this module -- we could for example redef Request in
	# main.zeek as needed.

	# State specific to the set_configuration request/response events
	type SetConfigurationState: record {
		config: ClusterController::Types::Configuration;
		requests: vector of Request &default=vector();
	};

	# State specific to supervisor interactions
	type SupervisorState: record {
		node: string;
	};

	# State for testing events
	type TestState: record {
	};

	# The redef is a workaround so we can use the Request type
	# while it is still being defined
	redef record Request += {
		results: ClusterController::Types::ResultVec &default=vector();
		finished: bool &default=F;

		set_configuration_state: SetConfigurationState &optional;
		supervisor_state: SupervisorState &optional;
		test_state: TestState &optional;
	};

	global null_req = Request($id="", $finished=T);

	global create: function(reqid: string &default=unique_id("")): Request;
	global lookup: function(reqid: string): Request;
	global finish: function(reqid: string): bool;

	global request_expired: event(req: Request);

	global is_null: function(request: Request): bool;
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
