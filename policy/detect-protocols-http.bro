# $Id: detect-protocols-http.bro,v 1.1.4.2 2006/05/31 00:16:21 sommer Exp $
#
# Identifies protocols that use HTTP.

@load detect-protocols

module DetectProtocolHTTP;

export {
	# Defines characteristics of a protocol.  All attributes must match
	# to trigger the detection. We match patterns against lower-case
	# versions of the data.
	type protocol : record {
		url: pattern &optional;
		client_header: pattern &optional;
		client_header_content: pattern &optional;
		server_header: pattern &optional;
		server_header_content: pattern &optional;
	};

	const protocols: table[string] of protocol = {
		["Kazaa"] = [$url=/^\/\.hash=.*/, $server_header=/^x-kazaa.*/],
		["Gnutella"] = [$url=/^\/(uri-res|gnutella).*/,
				$server_header=/^x-gnutella-.*/],
		["Gnutella_"] = [$url=/^\/(uri-res|gnutella).*/,
				$server_header=/^x-(content-urn|features).*/],
		["Gnutella__"] = [$url=/^\/(uri-res|gnutella).*/,
				$server_header=/^content-type/,
				$server_header_content=/.*x-gnutella.*/],
		["BitTorrent"] = [$url=/^.*\/(scrape|announce)\?.*info_hash.*/],
		["SOAP"] = [$client_header=/^([:print:]+-)?(soapaction|methodname|messagetype).*/],
		["Squid"] = [$server_header=/^x-squid.*/],
	} &redef;
}

# Bit masks.
const url_found = 1;
const client_header_found = 2;
const server_header_found = 2;

type index : record {
	id: conn_id;
	pid: string;
};

# Maps to characteristics found so far.
# FIXME: An integer would suffice for the bit-field
# if we had bit-operations ...
global conns: table[index] of set[count] &read_expire = 1hrs;

function check_match(c: connection, pid: string, mask: set[count])
	{
	conns[[$id=c$id, $pid=pid]] = mask;

	local p = protocols[pid];

	if ( p?$url && url_found !in mask )
		return;

	if ( p?$client_header && client_header_found !in mask )
		return;

	if ( p?$server_header && server_header_found !in mask )
		return;

	# All found.

	ProtocolDetector::found_protocol(c, ANALYZER_HTTP, pid);
	}

event http_request(c: connection, method: string, original_URI: string,
			unescaped_URI: string, version: string)
	{
	for ( pid in protocols )
		{
		local p = protocols[pid];

		if ( ! p?$url )
			next;

		local mask: set[count];
		local idx = [$id=c$id, $pid=pid];
		if ( idx in conns )
			mask = conns[idx];

		if ( url_found in mask )
			# Already found a match.
			next;

		# FIXME: There are people putting NULs into the URLs
		# (BitTorrent), which to_lower() does not like.  Not sure
		# what the right fix is, though.
		unescaped_URI = subst_string(unescaped_URI, "\x00", "");

		if ( to_lower(unescaped_URI) == p$url )
			{
			add mask[url_found];
			check_match(c, pid, mask);
			}
		}
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( name == /[sS][eE][rR][vV][eE][rR]/ )
		{
		# Try to extract the server software.
		local s = split1(strip(value), /[[:space:]\/]/);
		if ( s[1] == /[-a-zA-Z0-9_]+/ )
			ProtocolDetector::found_protocol(c, ANALYZER_HTTP, s[1]);
		}

	for ( pid in protocols )
		{
		local p = protocols[pid];

		local mask: set[count];
		local idx = [$id=c$id, $pid=pid];
		if ( idx in conns )
			mask = conns[idx];

		if ( p?$client_header && is_orig )
			{
			if ( client_header_found in mask )
				return;

			if ( to_lower(name) == p$client_header )
				{
				if ( p?$client_header_content )
					if ( to_lower(value) !=
					     p$client_header_content )
						return;

				add mask[client_header_found];
				check_match(c, pid, mask);
				}
			}

		if ( p?$server_header && ! is_orig )
			{
			if ( server_header_found in mask )
				return;

			if ( to_lower(name) == p$server_header )
				{
				if ( p?$server_header_content )
					if ( to_lower(value) !=
					     p$server_header_content )
						return;

				add mask[server_header_found];
				check_match(c, pid, mask);
				}
			}
		}
	}
