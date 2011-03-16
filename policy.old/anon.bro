# $Id: anon.bro 6889 2009-08-21 16:45:17Z vern $

redef anonymize_ip_addr = T;

const orig_addr_anonymization = RANDOM_MD5 &redef;
const resp_addr_anonymization = RANDOM_MD5 &redef;
const other_addr_anonymization = SEQUENTIALLY_NUMBERED &redef;

const preserve_orig_addr: set[addr] = {} &redef;
const preserve_resp_addr: set[addr] = {} &redef;
const preserve_other_addr: set[addr] = {
	0.0.0.0,
} &redef;

const preserved_subnet: set[subnet] = {
#	192.150.186/23,
} &redef;

const preserved_net: set[net] = {
#	192.150.186, 192.150.187,
} &redef;

global anon_log = open_log_file("anon") &redef;

global anonymized_args: table[string] of string;

global ip_anon_mapping: set[addr, addr];

event bro_init()
	{
	for ( n in preserved_net )
		preserve_net(n);
	}

function anonymize_address(a: addr, id: conn_id): addr
	{
	if ( a == id$orig_h )
		return anonymize_addr(a, ORIG_ADDR);
	else if ( a == id$resp_h )
		return anonymize_addr(a, RESP_ADDR);
	else
		return anonymize_addr(a, OTHER_ADDR);
	}

event anonymization_mapping(orig: addr, mapped: addr)
	{
	if ( [orig, mapped] !in ip_anon_mapping )
		{
		add ip_anon_mapping[orig, mapped];
		print anon_log, fmt("%s -> %s", orig, mapped);
		}
	}

function string_anonymized(from: string, to: string, seed: count)
	{
	print anon_log, fmt("\"%s\" %d=> \"%s\"", from, seed, to);
	}

global num_string_id: count = 0 &redef;
global anonymized_strings: table[string] of record {
	s: string;
	c: count;
} &redef;

# Hopefully, the total number of strings to anonymize is much less than
# 36^unique_string_length.
const unique_string_length = 8 &redef;
# const anonymized_string_pattern = /U[0-9a-f]+U/;
global unique_string_set: set[string];

event bro_init()
	{
	for ( s in anonymized_strings )
		add unique_string_set[anonymized_strings[s]$s];
	}

function unique_string(s: string, seed: count): string
	{
	local t = cat("U", sub_bytes(md5_hmac(seed, s),
					1, unique_string_length), "U");
	if ( t in unique_string_set )
		return unique_string(s, seed+1);

	anonymized_strings[s] = [$s = t, $c = 1];
	add unique_string_set[t];
	string_anonymized(s, t, seed);

	return t;
	}

function anonymize_string(from: string): string
	{
	if ( from in anonymized_strings )
		{
		++anonymized_strings[from]$c;
		return anonymized_strings[from]$s;
		}

	local t = unique_string(from, 0);
	return t;
	}

function anonymize_arg(typ: string, arg: string): string
	{
	if ( arg == "" )
		return "";	# an empty argument is safe

	local arg_seed = string_cat(typ, arg);

	if ( arg_seed in anonymized_args )
		return anonymized_args[arg_seed];

	local a = anonymize_string(arg_seed);
	anonymized_args[arg_seed] = a;

	print anon_log, fmt("anonymize_arg: (%s) {%s} -> %s ",
			typ, to_string_literal(arg), to_string_literal(a));
	return a;
	}


# Does not contain ? and ends with an allowed suffix.
const path_to_file_pat = 
	/\/[^?]+\.(html|ico|icon|pdf|ps|doc|ppt|htm|js|crl|swf|shtml|h|old|c|cc|java|class|src|cfm|gif|jpg|php|rdf|rss|asp|bmp|owl|phtml|jpeg|jsp|cgi|png|txt|xml|css|avi|tex|dvi)/
	;

# Acceptable domain names.
const kosher_dom_pat =
	/ar|au|biz|br|ca|cc|cl|cn|co|com|cx|cz|de|ec|es|edu|fi|fm|fr|gov|hn|il|is|it|jp|lv|mx|net|no|nz|org|pe|pl|ru|sk|tv|tw|uk|us|arpa/
	;

# Simple filename pattern.
const simple_filename = 
	/[0-9\-A-Za-z]+\.(html|ico|icon|pdf|ps|doc|ppt|htm|js|crl|swf|shtml|h|old|c|cc|java|class|src|cfm|gif|jpg|php|rdf|rss|asp|bmp|owl|phtml|jpeg|jsp|cgi|png|txt|xml|css|avi|tex|dvi)/
	;

function anonymize_path(path: string): string
	{
	local hashed_path = "";

	if ( to_lower(path) != path_to_file_pat )
		{
		hashed_path = anonymize_arg("path", path);
		return hashed_path;
		}

	local file_parts = split(path, /\./);

	local i = 1;
	for ( part in file_parts )
		{
		# This looks broken to me - VP.
		hashed_path = fmt("%s.%s", hashed_path, file_parts[i]);
		if ( ++i == length(file_parts) )
			break;
		}

	return fmt("%s.%s", anonymize_arg("path", hashed_path), file_parts[i]);
	}

function anonymize_host(host: string): string
	{
	local hashed_host = "";
	local host_parts = split(host, /\./);

	local i = 1;
	for ( hosty in host_parts )
		{
		if ( i == length(host_parts) )
			break;

		# Check against "kosher" tld list.
		hashed_host = fmt("%s%s.", hashed_host,
					anonymize_arg("host", host_parts[i]));

		++i;
		} 

	if ( host_parts[i] == kosher_dom_pat )
		return string_cat(hashed_host, host_parts[i]);

	print anon_log, fmt("anonymize_host: non-kosher domain %s", host); 
	return string_cat(hashed_host, anonymize_arg("host", host_parts[i]));
	}

event bro_done()
	{
	for ( s in anonymized_strings )
		{
		print anon_log, fmt("appearance: %d: \"%s\" => \"%s\"",
			anonymized_strings[s]$c, s, anonymized_strings[s]$s);
		}
	}
