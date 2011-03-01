# $Id:$

@load anon

global http_anon_log = open_log_file("http-anon") &redef;

const URI_proto_pat = /^ *([a-zA-Z]+)\:\/\// ;
const known_URI_proto_pat = /^ *(http|https|ftp|ssh)\:\/\// ;

const host_pat = / *^([\-0-9a-zA-Z]+\.)+([\_\-0-9a-zA-Z])*/ ;
const port_pat = /^ *(\:[0-9]+\.)/ ;

const query_pat = /\?/ ;

function anonymize_http_URI(URI: string): string
	{
	URI = to_lower(URI);

	# Strip off protocol.
	local proto = "";
	if ( URI_proto_pat in URI )
		{
		local proto_part = split(URI, /\:\/\//);

		# Check if we know the protocol.  If not, flag it so we
		# can update our protocol database.

		if ( known_URI_proto_pat !in URI )
			{
			print http_anon_log,
				fmt("*** protocol %s unknown ", proto_part[1]);

			proto_part[1] =
				string_cat(" (bro: unknown) ",
					anonymize_arg("proto", proto_part[1]));
			}

		proto = string_cat(proto_part[1],"://");
		URI = proto_part[2];
		}

	# Strip off domain.
	local host = "";
	if ( host_pat in URI )
		{
		local base_parts =
			split_all(URI, / *^([\-\_0-9a-z]+\.)+[\-\_0-9a-z]*/);

		if ( |base_parts| < 2 )
			{
			print http_anon_log,
				fmt (" XXXXXXXXXXXXXXXXXXXXXX BASE %s", URI);
			return " XXXX processing error XXXX";
			}

		if ( |base_parts| == 2 )
			URI =  "";

		else if ( |base_parts| == 3)
			URI = base_parts[3];

		else if ( |base_parts| > 3)
			{
			local patch_me = "";
			local hack = base_parts[2];

			local i = 1;
			for ( part in base_parts )
				{
				if ( i != 2 )
					patch_me = string_cat(patch_me,
								base_parts[i]);
				i += 1;
				}

			URI  = patch_me;
			}

		if ( host == simple_filename )
			host = anonymize_path(host);
		else
			host = anonymize_host(base_parts[2]);
		}

	# Strip off port (if it exists).
	local pport = "";
	if ( port_pat in URI )
		{
		print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX ";
		print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX ";
		print "XXXXX anon.bro doing nothing with port XXXXXXXXXXX ";
		print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX ";
		print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX ";
		}

	# Handle query (if exists).
	local tail = "";
	if ( URI == "/" )
		{
		# -- pass
		}

	else if ( query_pat in URI )
		{
		local query_part = split(URI, /\?/);

		tail = fmt("%s?%s",
				anonymize_path(query_part[1]),
				anonymize_path(query_part[2]));
		}

	else
		tail = anonymize_path(URI);

	tail = string_cat("/", tail);

	return fmt("%s%s%s%s", proto, host, pport, tail);
	}


const a_href_pat = /.*\< *a *href.*\>.*/ ;
	#/.*\< *a *href *= *\"[[:print:]]+\" *\>.*/;

# Doesn't get everything ... but works for most.
const a_href_split =
	/\< *a *href *= *(\\)?(\"|\')?([0-9a-z\/._!\[\]():*;~&|$\\=+\-?%@])+(\\)?(\"|\')?/ ;

# Elegant ... yeah ... really .. :-/
const file_split =
	/(\"|\')([0-9a-z\/._!\[\]():*;~&|$\\=+\-?%@])+(\"|\')/ ;
const file_strip_split = /([0-9a-z\/._!\[\]():*;~&|$\\=+\-?%@])+/ ;

function http_doc_link_list(abstract: string): string
	{
	abstract = to_lower(abstract);

	if ( abstract == "" )
		return abstract;

	local concat_key = "";
	local href_parts = split_all(abstract, a_href_split);

	for ( part in href_parts )
		{
		if ( href_parts[part] == a_href_split )
			{
			local file_parts =
				split_all(href_parts[part], file_split);
			for ( a_part in file_parts )
				{
				if ( file_parts[a_part] == file_split )
					{
					local file_strip_parts =
						split_all(file_parts[a_part],
							file_strip_split);
					concat_key = fmt("%s %s", concat_key,
							anonymize_http_URI(file_strip_parts[2]));
					}
				}
			}
		}

	return concat_key;
	}
