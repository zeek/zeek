##! This module implements a request state abstraction in the Management
##! framework that both controller and agent use to connect request events to
##! subsequent response ones, and to be able to time out such requests.

@load ./config
@load ./types

module Management::Request;

export {
	## Request records track state associated with a request/response event
	## pair. Calls to
	## :zeek:see:`Management::Request::create` establish such state
	## when an entity sends off a request event, while
	## :zeek:see:`Management::Request::finish` clears the state when
	## a corresponding response event comes in, or the state times out.
	type Request: record {
		## Each request has a hopefully unique ID provided by the requester.
		id: string;

		## For requests that result based upon another request (such as when
		## the controller sends requests to agents based on a request it
		## received by the client), this specifies that original, "parent"
		## request.
		parent_id: string &optional;

		## The results vector builds up the list of results we eventually
		## send to the requestor when we have processed the request.
		results: Management::ResultVec &default=vector();

		## An internal flag to track whether a request is complete.
		finished: bool &default=F;
	};

	# To allow a callback to refer to Requests, the Request type must
	# exist. So redef to add it:
	redef record Request += {
		## A callback to invoke when this request is finished via
		## :zeek:see:`Management::Request::finish`.
		finish: function(req: Management::Request::Request) &optional;
	};

	## The timeout interval for request state. Such state (see the
	## :zeek:see:`Management::Request` module) ties together request and
	## response event pairs. A timeout causes cleanup of request state if
	## regular request/response processing hasn't already done so. It
	## applies both to request state kept in the controller and the agent,
	## though the two use different timeout values: agent-side requests time
	## out more quickly. This allows agents to send more meaningful error
	## messages, while the controller's timeouts serve as a last resort to
	## ensure response to the client.
	const timeout_interval = 10sec &redef;

	## A token request that serves as a null/nonexistent request.
	global null_req = Request($id="", $finished=T);

	## This function establishes request state.
	##
	## reqid: the identifier to use for the request.
	##
	global create: function(reqid: string &default=unique_id("")): Request;

	## This function looks up the request for a given request ID and returns
	## it. When no such request exists, returns Management::Request::null_req.
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
	## Management::Request::timeout_interval) before it has been finished via
	## Management::Request::finish().
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
	# No need to flag request expiration when we've already internally marked
	# the request as done.
	if ( ! reqs[reqid]$finished )
		event Management::Request::request_expired(reqs[reqid]);

	return 0secs;
	}

# This is the global request-tracking table. The table maps from request ID
# strings to corresponding Request records. Entries time out after the
# Management::Request::timeout_interval. Upon expiration, a request_expired
# event triggers that conveys the request state.
global g_requests: table[string] of Request
    &create_expire=timeout_interval &expire_func=requests_expire_func;

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

	if ( req?$finish )
		req$finish(req);

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
	local parent_id = "";

	if ( request?$parent_id )
		parent_id = fmt(" (via %s)", request$parent_id);

	return fmt("[request %s%s %s, results: %s]", request$id, parent_id,
	           request$finished ? "finished" : "pending",
		   Management::result_vec_to_string(request$results));
	}
