# $Id: proxy.bro,v 1.1.4.2 2006/05/31 00:16:22 sommer Exp $
#
# Finds open proxies by matching incoming HTTP requests with outgoing ones.

@load notice

module Proxy;

export {
	const KnownProxies: set[addr] = { };

	redef enum Notice += {
		HTTPProxyFound,
	};
}


type request: record {
	p: port;
	paths: set[string];
};

# Maps the address of the potential proxy to the paths that
# have been requested from it.
global requests: table[addr] of request;

# A parsed URL.
type url: record {
	host: string;
	path: string;
};

global found_proxies: set[addr] &create_expire = 24 hrs;

function parse_url(u: string) : url
	{
	# The URL parsing is imperfect, but should work sufficiently well.
	local a = split1(u, /:\/\//);
	if ( |a| == 1 )
		return [$host="", $path=a[1]];

	local b = split1(a[2], /\//);
	return [$host=b[1], $path=(|b| == 2 ? cat("/", b[2]) : "/")];
	}

event http_request(c: connection, method: string, original_URI: string,
			unescaped_URI: string, version: string)
	{
	if ( method != "GET" && method != "CONNECT" )
		return;

	local client = c$id$orig_h;
	local server = c$id$resp_h;

	if ( server in KnownProxies )
		return;

	# FIXME: Which one? original_URI or unescaped_URI?
	local u = parse_url(original_URI);

	if ( client in requests )
		{
		# We have already seen requests to this host.  Let's see
		# any matches the one we're very currently seeing.
		local r = requests[client];
		if ( u$path in r$paths )
			{
			if ( client !in found_proxies )
				{
				NOTICE([$note=HTTPProxyFound,
						$conn=c, $src=client,
						$p=r$p, $URL=original_URI,
						$msg=fmt("HTTP proxy found %s:%d (%s)",
						client, r$p, original_URI)]);
				add found_proxies[client];
				}

			return;
			}
		}

	if ( u$host == "" )
		# A relative URL. That's fine.
		return;

	# An absolute URL.  Remember path for later.
	#
	# Note: using "when", could even lookup the destination
	# host and remember that one, too!

	if ( server !in requests )
		{
		local empty_set: set[string] &read_expire = 15 secs;
		local req = [$p=c$id$resp_p, $paths=empty_set];
		requests[server] = req;
		}

	add requests[server]$paths[u$path];
	}
