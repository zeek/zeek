# $Id: ftp-reply-pattern.bro 6 2004-04-30 00:31:26Z jason $

@load ftp-anonymizer

redef process_ftp_reply_by_message_pattern = T;


# A line of reply message is split into fields with the following
# regular expression.  The regular expression defines the pattern of
# field separators. Basically a field separator is blank space
# enclosed by optional punctuations.

const ftp_msg_field_separator =
	  /@@BOL@@ [[:space:][:punct:]]*( @@EOL@@)?/
	| /[[:space:][:punct:]]+/
	| /[[:space:][:punct:]]* @@EOL@@/
	;

# Type *msg_format_info* defines a message format extracted from
# messages.

type msg_format_info: record {
	parts: string_array;
	code: count;
	msg: string;		# one of the original messages
	hit: count;		# number of messages that match the pattern
};

type msg_format_group: table[string] of msg_format_info;
global msg_format_groups: table[string] of msg_format_group;


# A pattern string (derived from one or more message formats) contains
# fields enclosed by '|': e.g.
#
#  "211 @@BOL@@ |connected| |to| |~ domain, ~ ip| @@EOL@@"
#
# Thus we the field separator can be defined by the following pattern:
# everything up to the first '|', after the last '|', or between two
# adjacent '|'s in the middle.

const ftp_pattern_field_separator =
	  /@@BOL@@ @@EOL@@/
	| /@@BOL@@ [^|]*\|/
	| /\|[^|]+\|/
	| /\|[^|]* @@EOL@@/
	;

# A message pattern is very similar to a message format, except that
# the former is for message pattern matching and thus is used in a
# different phase than a message format, which is used in pattern
# extraction.

type msg_pattern_info: record {
	code: count;
	str: string;
	num_parts: count;
	parts: string_array;
	sep: string_array;
	tok: string_array;
	hit: count;
};

type msg_pattern_group: table[string] of msg_pattern_info;
global msg_pattern_groups: table[string] of msg_pattern_group;


# Here starts patterns of individual fields (numbers, ip address, domain
# name, etc.) in the reply message:

# Numbers (including float numbers and negative numbers)
const ftp_number_pat = /[\-]?[0-9]+(\.[0-9]+)?/;

# English words (including 's and 't)
# const ftp_word_pat =
	/[[:alpha:]]*('m|'re|[[:alpha:]]'s|s'|n't|'d|'ve|'ll)|[[:alpha:]]+/
	;

# File modes in ls -l (seen in replies for STAT)
const ftp_file_mode_pat = /[ld\-]([r-][w-][xs-]){3}/;

# FTP server version string
const ftp_server_version_pat = /[a-zA-Z0-9]+([\.\-_][a-zA-Z0-9]+)+/ &redef;

# FTP path name
#
# As it is not clear how to define a pattern for path names, it is
# defined in two aspects: first, we define a pattern for strings that
# are path names *almost for sure*:

const ftp_path_pat = /\/.+\/.*/
	| /README/
	| /.*\.(gz|tar|Z|ps|pdf)/ 	# TODO: add other extensions
	| /[A-Z]:[\\\/].*/ 		# a path name almost for sure
	;

# Second, we define a pattern for strings that can possibly be a path name:
# const ftp_file_name_pat = /[[:print:]]+/;
#
# Together, we assume that
# Set(ftp_path_pat) <= Set(path names) <= Set(ftp_file_name_pat)

# DOS file names
const ftp_dos_path_pat = /[A-Z]:[\\\/].*/;


# Finally, a table of message field patterns
const ftp_msg_part_patterns = {
	["~ num"] = ftp_number_pat,
	["~ port"] = ftp_port_pat,
	["~ ip"] = ftp_ip_pat,
	["~ domain"] = ftp_domain_name_pat,
	["~ file_mode"] = ftp_file_mode_pat,
	["~ time"] = /[0-9]{2}:[0-9]{2}(:[0-9]{2})?(am|pm)?/,
	["~ day"] = /Mon|Tue|Wed|Thu|Fri|Sat|Sun/,
	["~ month"] = /Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec/,
	["~ ip,port"] = /[0-9]{1,3}(\.[0-9]{1,3}){3},[0-9]+/,
	["~ ip:port"] = /[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]+/,
	["~ email"] = /[[:alnum:]\-\._]+@([\-0-9a-zA-Z]+\.)*[\-0-9a-zA-Z]+/,
	["~ path"] = ftp_path_pat,
	["~ url"] = /http:\/\/.+/,
} &redef;


# One critical issue in understanding an FTP reply message is to
# recognize the request arguments in messages. The argument of an FTP
# request may appear in various forms in the reply message,
# e.g. argument "/abc//def/" may appear as "/abc/def/" (eliminate
# duplicat /), "/abc/def" (w/o last /), or even "def" (base file name
# only).

# Type *ftp_arg_variant* defines the set of variants of an argument,
# and function *expand_ftp_arg_variants* expands an argument to
# its variants.

type ftp_arg_variants: record {
	arg: string;		# the argument
	path: string;		# after eliminating options
	norm_path: string;	# normalized path, after eliminating dup slashes
	abs_path: string;	# the absolute path
	base_path: string;	# the base file name only, without the directory part
};


# Trace-specific anonymization of replies
# 1. Whether function anonymize_trace_specific_reply is defined:
const trace_specific_reply_anonymization = F &redef;

# 2. Result of message anonymization
type ftp_reply_anon_result: record {
	anonymized: bool;
	msg: string;
};

# 3. The trace-specific function (to be defined externally)
global anonymize_trace_specific_reply:
	function(session: ftp_session_info, code: count, msg: string,
		cmd_arg: ftp_cmd_arg,
		arg_var: ftp_arg_variants): ftp_reply_anon_result;


# Other global states:

# Reply messages that are entirely stripped out (e.g. server banner message)
global msg_stripped_out: set[string];

# Remember wildcard matches to suppress the number of outputs
global all_wildcard_matches: set[string, string];


# PART I. Message pattern extraction

function init_msg_format_info(parts: string_array, code: count, msg: string, level: count): msg_format_info
	{
	return [$parts = parts,
		$code = code,
		$msg = msg,
		$hit = 0];
	}


# Whether the pattern defined by *parts* is a sub-pattern of
# *fmt_parts*.

function match_msg_format(fmt_parts: string_array, parts: string_array): bool
	{
	if ( length(fmt_parts) != length(parts) )
		return F;

	for ( i in fmt_parts )
		{
		if ( i % 2 == 1 )
			{
			local t1 = fmt_parts[i];
			local t2 = parts[i];

			if ( t1 == t2 || t1 == "~ *" ||
			     (t1 == "~ path" &&
			      (t2 == ftp_file_name_pat || t2 == "~ num")) )
				; # t2 matches t1
			else
				return F;
			}
		}

	return T;
	}


# Abstract msg_parts[k]. The whole msg_parts is passed because the
# function needs to look at the context to decide whether a pattern is
# applicable (in the case of version pattern).

function abstract_msg_part(msg_parts: string_array, k: count, other_pat: table[string] of string): string
	{
	local part = msg_parts[k];
	local abs_part: string;

	if ( part in other_pat )
		abs_part = other_pat[part];
	else if ( k > 2 &&
		  msg_parts[int_to_count(k-2)] == /[Vv]er(sion)?|[Rr]elease|.*ftpd.*|Server|Process/ &&
		  part == ftp_server_version_pat &&
		  part != ftp_domain_name_pat )
		abs_part = "~ version";
	else if ( part == ftp_msg_part_patterns["~ path"] &&
		  part == ftp_file_name_pat )
		abs_part = "~ path";
	else
		{
		local known_pattern = 0;

		for ( pat_ty in ftp_msg_part_patterns )
			if ( part == ftp_msg_part_patterns[pat_ty] )
				{
				++known_pattern;
				abs_part = pat_ty;
				}
		if ( known_pattern > 1 )
			print ftp_anon_log,
			    fmt("ERROR: ambiguous ftp msg part pattern: %s", part);
		if ( known_pattern != 1 )
			abs_part = part;
		}

	return abs_part;
	}


# Transform a message format to a pattern string.

function fmt_parts_to_string(parts: string_array): string
	{
	local p: string_array;
	local num_parts = length(parts);
	for ( i in parts )
		{
		local s = parts[i];

		if ( i == 1 || i == num_parts )
			p[i] = "";
		else if ( i % 2 == 1 )
			p[i] = string_cat("|", to_lower(s), "|");
		else
			p[i] = " ";
		}
	return string_cat("@@BOL@@", cat_string_array(p), "@@EOL@@");
	}


# Extract the format of a message, if it does not match any known
# format. The message is already splitted into *msg_parts*, and the
# *act_msg* is only used for logging and debugging. Parameter
# *other_pat* defines an instance-specific mapping from strings to
# field types (e.g. "~ cmd", "~ arg"). For example, when "/fileA" is
# the argument of the corresponding FTP requests, other_pat["/fileA"]
# = "~ arg".

function extract_ftp_reply_pattern(code: count, act_msg: string, msg_parts: string_array,
			other_pat: table[string] of string,
			session: ftp_session_info): bool
	{
	local num_parts = length(msg_parts);

	# Abstract each part of the message.
	local abs_parts: string_array;
	for ( i in msg_parts )
		{
		if ( i % 2 == 1 )
			abs_parts[i] = abstract_msg_part(msg_parts, i, other_pat);
		else
			abs_parts[i] = msg_parts[i];
		}

	# Derive the abstract message format
	local abs_msg = fmt_parts_to_string(abs_parts);

	# Locate the corresponding format group
	local ind = fmt("%3d %3d", code, num_parts);
	local fmt_group: msg_format_group;

	if ( ind in msg_format_groups )
		fmt_group = msg_format_groups[ind];
	else
		msg_format_groups[ind] = fmt_group;

	# Check existing message formats
	if ( abs_msg in fmt_group )
		{
		++fmt_group[abs_msg]$hit;
		return F;
		}

	local the_fmt = init_msg_format_info(abs_parts, code,
				fmt("%s: %s", id_string(session$connection_id), act_msg), 1);
	the_fmt$hit = 1;

	# Check whether it is a sub-format of a known format, or vice versa

	# Whether the_fmt is a sub-format of another format
	local sub_format = F;

	# Which other formats are sub-formats of the_fmt
	local sub_format_set: set[string];

	for ( fm2 in fmt_group )
		{
		local f2 = fmt_group[fm2];
		if ( match_msg_format(f2$parts, abs_parts) )
			{
			sub_format = T;	# abs_parts is a sub-format of f2
			++f2$hit;
			}
		else if ( match_msg_format(abs_parts, f2$parts) )
			add sub_format_set[fm2];
		else
			; # do nothing
		}

	# Do not add the format if it is a sub-format of another one.
	if ( ! sub_format )
		{
		fmt_group[abs_msg] = the_fmt;

		# remove sub-formats of this message
		for ( fm3 in sub_format_set )
			{
			the_fmt$hit = the_fmt$hit + fmt_group[fm3]$hit;
			delete fmt_group[fm3];
			}
		}

	return T;
	}

function print_msg_format(the_log: file, ind: string, m: string, f: msg_format_info)
	{
	local lm = to_string_literal(m);
	if ( lm != m )
		print the_log, fmt("special_character_in_pattern: \"%s\"", lm);
	local fm = fmt("%d %s", f$code, lm);
	local pat_ind = fmt("%3d %3d", f$code, length(f$parts));

	print the_log, fmt("reply_pattern: $%s$ \"%s\",  # \"%s\"",
		ind, fm, f$msg);

	if ( pat_ind in msg_pattern_groups && fm in msg_pattern_groups[pat_ind] )
		print the_log, fmt("ERROR: pattern_already_exists: \"%s\"", fm);
	}

event bro_done()
	{
	for ( ind in msg_format_groups )
		{
		local fmt_group = msg_format_groups[ind];
		for ( m2 in fmt_group )
			print_msg_format(ftp_anon_log, ind, m2, fmt_group[m2]);
		}
	}


# PART II. Read and parse patterns

type msg_pattern_result: record {
	valid: bool,
	msg_pat: msg_pattern_info,
};


# Parse message pattern string <fm> -- put the separators in <sep> and
# tokens in <tok>.

function parse_msg_format(fm: string): msg_pattern_result
	{
	local msg_pat: msg_pattern_info;
	local ret = [$valid = F, $msg_pat = msg_pat];

	# Separate the reply code from the rest of the pattern string
	local code_fmt = split1(fm, / /);
	local sep: string_array;
	local tok: string_array;

	msg_pat$code = to_count(code_fmt[1]);
	msg_pat$str = fm;
	# print ftp_anon_log, fmt("msg_format: %d \"%s\"", msg_pat$code, msg_pat$str);
	msg_pat$sep = sep;
	msg_pat$tok = tok;
	msg_pat$hit = 0;

	# Split the pattern string with the pattern field separator
	local parts = split_all(code_fmt[2], ftp_pattern_field_separator);
	local num_parts = length(parts);
	msg_pat$parts = parts;
	msg_pat$num_parts = num_parts;

	for ( i in parts )
		{
		local s = parts[i];
		local j: count;
		if ( i % 2 == 0 )
			{
			j = int_to_count(i / 2);
			sep[j] = s;
			}
		else if ( i > 1 && i < num_parts )
			{
			j = int_to_count((i - 1) / 2);
			tok[j] = s;
			}
		else
			; # do nothing
		}

	ret$valid = T;
	return ret;
	}


# Parse the pattern string and insert the pattern into
# msg_pattern_groups.

function process_predefined_msg_format(f: string): bool
	{
	local r: msg_pattern_result;
	r = parse_msg_format(f);
	if ( ! r$valid )
		return F;
	local msg_pat = r$msg_pat;

	local pat_ind = fmt("%3d %3d", msg_pat$code, msg_pat$num_parts);

	local pat_group: msg_pattern_group;
	if ( pat_ind !in msg_pattern_groups )
		msg_pattern_groups[pat_ind] = pat_group;
	else
		pat_group = msg_pattern_groups[pat_ind];

	if ( msg_pat$str in pat_group )
		return F;	# there should not be duplicates
	pat_group[msg_pat$str] = msg_pat;

	return T;
	}

const ftp_msg_format_white_list: set[string] = {} &redef;

event bro_init()
	{
	for ( f in ftp_msg_format_white_list )
		process_predefined_msg_format(f);
	}


# PART III. Merge message patterns

# moved to ftp-merge-pattern.bro

# PART IV. Message pattern matching

# Note that $parts is not redundant with $pat, because each field in
# $pat may contain multiple patterns, as in
#
# "211 @@BOL@@ |connected| |to| |~ domain, ~ ip| @@EOL@@"
#
# $parts tells whether "~ domain" or "~ ip" is matched.

type msg_pattern_match_result: record {
	valid: bool;
	pat: msg_pattern_info;	# the pattern matched
	parts: string_array;	# the matched pattern of each part
};


# Return -1 if t1 is more specific than t2, 1 if vice versa, and 0 if
# t1 equals to t2 or if t1 and t2 are incomparable.

function cmp_pattern_part(t1: string, t2: string): int
	{
	if ( t1 == t2 ) return 0;

	local ret: int = 0;

	if ( t1 != /~ .*/ || t2 != /~ .*/ )
		{
		if ( t2	== /~ .*/ ) ret = -1; 	# t1 < t2
		if ( t1 == /~ .*/ ) ret = 1; 	# t2 < t1
		}
	else if ( t1 == /~ (arg|cmd)/ || t2 == /~ (arg|cmd)/ )
		{
		if ( t2 != /~ (arg|cmd)/ ) ret = -1;	# t1 < t2
		if ( t1 != /~ (arg|cmd)/ ) ret = 1; 	# t2 < t1
		}
	else if ( t1 == "~ ip" && t2 == "~ domain" )
		ret = -1;
	else if ( t1 == "~ domain" && t2 == "~ ip" )
		ret =  1;
	else if ( t1 == "~ *" || t2 == "~ *" )
		{
		if ( t1 != "~ *" ) ret = -1;
		if ( t2 != "~ *" ) ret = 1;
		}

	# print ftp_anon_log,
	#	fmt("compare pattern part: \"%s\" vs. \"%s\" = %d", t1, t2, ret);

	if ( ret == 0 )
		print ftp_anon_log,
			fmt("ERROR: cannot compare pattern part: \"%s\" vs. \"%s\"", t1, t2);
	return ret;
	}


# Which pattern is more specific, returns -1 if m1 < m2, ...

function cmp_msg_pattern_match(m1: msg_pattern_match_result, m2: msg_pattern_match_result): int
	{
	local b1 = F;	# whether part of m1 is more specific
	local b2 = F;	# whether part of m2 is more specific

	for ( i in m1$parts )
		{
		local c = cmp_pattern_part(m1$parts[i], m2$parts[i]);
		if ( c < 0 ) b1 = T;
		if ( c > 0 ) b2 = T;
		}
	if ( b1 && ! b2 ) return -1;
	if ( ! b1 && b2 ) return 1;

	print ftp_anon_log,
		fmt("ERROR: cannot compare pattern match: \"%s\" vs. \"%s\"", m1$pat$str, m2$pat$str);
	return 0;
	}


# Whether data matches pat. Parameter aux_pat contains a set of (data,
# pat) pairs in addition to the predefined patterns and usually
# contains pairs such as "~ cmd : USER", "~ arg : anonymous".

function do_match_pattern_part(pat: string, data: string, aux_pat: set[string]): bool
	{
	if ( pat == /~ .+[-+]/ ) 	# with a flag
		pat = cut_tail(pat, 1); # ignore the flag

	if ( string_cat(pat, " : ", data) in aux_pat )
		return T;
	else if ( pat != /~ .*/ ) # not an abstract pattern
		{
		return ( to_lower(data) == pat );
		}
	else if ( pat == "~ *" )
		return T; 	# always match
	else if ( pat == "~ path" )
		{
		return ( data == ftp_file_name_pat ||
		         /\// in data || /\\ / in data );
		}
	else if ( pat == "~ domain" )
		{
		return ( data == /([\-0-9a-zA-Z]+\.)*[\-0-9a-zA-Z]+/ );
		}
	else if ( pat == "~ version" )
		{
		return ( data == /[A-Za-z0-9\-\.\_]+/ );
		}
	else if ( pat in ftp_msg_part_patterns )
		{
		return ( data == ftp_msg_part_patterns[pat] );
		}
	else
		return F;
	}


# Return the most promising part of <pat> that matches <data>, where
# <pat> = "<pat_1>, [<pat_2>, ...]".

function match_pattern_part(pat: string, data: string, aux_pat: set[string]): string
	{
	# print ftp_anon_log, fmt("part_match: \"%s\" ~? \"%s\"", data, pat);

	local best = "~ none";
	local pp = split(pat, /, /);
	for ( i in pp )
		{
		local p = pp[i];
		if ( do_match_pattern_part(p, data, aux_pat) )
			{
			if ( best == "~ none" || cmp_pattern_part(best, p) > 0 )
				best = p;
			}
		}

	# if ( best != "~ none" )
	#	print ftp_anon_log, fmt("part_match: \"%s\" ~ \"%s\"", data, best);

	return best;
	}


# Return T if the message (act_msg) matches the pattern; otherwise
# return F.

function do_msg_pattern_match(act_msg: string, msg_parts: string_array,
		msg_pat: msg_pattern_info, aux_pat: set[string]): msg_pattern_match_result
	{
	local ret: msg_pattern_match_result;
	ret$valid = F;

	local num_parts = length(msg_parts);
	local pat = msg_pat$tok;

	local data: string_array;
	for ( i2 in msg_parts )
		if ( i2 % 2 == 1 && i2 > 1 && i2 < num_parts )
			data[int_to_count((i2-1)/2)] = msg_parts[i2];

	if ( length(pat) != length(data) )
		return ret;

	local matched: string_array;

	for ( i in pat )
		{
		local m = match_pattern_part(pat[i], data[i], aux_pat);
		if ( m == "~ none" )
			return ret;
		matched[i] = m;
		}

	ret$valid = T;
	ret$parts = matched;
	ret$pat = msg_pat;
	return ret;
	}


# Anonymize a data field according to its pattern type.

function anonymize_msg_part(data: string, pat: string,
		cmd_arg: ftp_cmd_arg, session: ftp_session_info): string
	{
	if ( pat == /~ .+[-+]/ )
		{
		local pat_len = byte_len(pat);
		local annotation = sub_bytes(pat, pat_len, 1); # the last character
		if ( annotation == "+" ) 	# to expose the data
			return data;
		else if ( annotation == "-" )	# to hide the data
			return "<->";
		pat = cut_tail(pat, 1);		# otherwise ignore the annotation
		}

	if ( pat == "~ cmd" )
		return cmd_arg$anonymized_cmd;
	else if ( pat == "~ arg" )
		return cmd_arg$anonymized_arg;
	else if ( pat == "~ num" )
		return "<num>";			# hide the number by default
	else if ( pat == "~ port" )
		return anonymize_port_arg(session, "<port in reply>", data);
	else if ( pat == "~ ip" )
		{
		local a = parse_dotted_addr(data);
		return cat(anonymize_address(a, session$connection_id));
		}
	else if ( pat == "~ domain" )
		return "<domain>";
	else if ( pat == "~ file_mode" )
		return "<file mode>";
	else if ( pat == "~ time" || pat == "~ day" || pat == "~ month" )
		return data;
	else if ( pat == "~ email" )
		return "<email>";
	else if ( pat == "~ url" )
		return "<url>";
	else if ( pat == "~ ip,port" || pat == "~ ip:port" )
		{
		local b = split_all(data, /[:,]/);
		b[1] = cat(anonymize_address(parse_dotted_addr(b[1]), session$connection_id));
		return cat_string_array(b);
		}
	else if ( pat == "~ path" || pat == "~ dir" )
		return anonymize_file_name_arg(session, "<ftp reply>", data,
			(session$reply_code >= 100 && session$reply_code < 300));
	else if ( pat == "~ version" )
		return data; 	# keep version of the server
	else if ( pat == "~ *" )
		return "<*>";
	else
		{
		return "<!>";
		print ftp_anon_log, fmt("ERROR: do not know how to anonymize pattern: %s", pat);
		}
	}


# Compute a unique id that does not appear in <context>.

function get_unique_subst_id(context: string, seed: string): string
	{
	local id = string_cat("X", md5_hmac(seed), "X");
	if ( strstr(context, id) > 0 )
		return get_unique_subst_id(context, string_cat(seed, "."));
	return id;
	}


# Substitute all occurances of <part> in <msg1> with a unique id, if
# the occurrance of <part> is followed by <suffix> (context-sensitive
# substitution), and add to <subst_map> the mapping <subst_id> ->
# <part>. It returns the message after substitution.

function subst_part(msg1: string, part: string, suffix: string, subst_map: table[string] of string): string
	{
	local ps = string_cat(part, suffix);
	if ( strstr(msg1, ps) <= 0 ) return msg1;
	local subst_id = get_unique_subst_id(msg1, part);
	subst_map[subst_id] = part;
	return subst_string(msg1, ps, string_cat(subst_id, suffix));
	}


# Expand argument variants (see comments of ftp_arg_variants).

function expand_ftp_arg_variants(session: ftp_session_info, cmd_arg: ftp_cmd_arg): ftp_arg_variants
	{
	local var: ftp_arg_variants;

	var$arg = cmd_arg$arg;
	var$path = "~ none";
	var$norm_path = "~ none";
	var$abs_path = "~ none";
	var$base_path = "~ none";

	if ( cmd_arg$cmd in ftp_cmds_with_file_arg )
		{
		local opt_fn = separate_option_str(cmd_arg$arg);
		var$path = opt_fn$file_name;

		# eliminate duplicate slashes
		local norm_path = subst(var$path, /\/+|\\+/, "/");
		# eliminate '/./' (as '/')
		norm_path = subst(norm_path, /\/(\.\/)+/, "/");
		if ( norm_path == /.*\/\./ ) # end with '/.'
			norm_path = cut_tail(norm_path, 1);

		# compress ..
		norm_path = compress_path(norm_path);

		if ( var$path == ftp_dos_path_pat )
			{
			norm_path = subst(norm_path, /\//, "\\");
			# cut the last '\' off if it is not "C:\"
			if ( norm_path == /.*\\/ && norm_path != /[[:alpha:]]:\\/ )
				norm_path = cut_tail(norm_path, 1);
			}
		else
			{
			if ( norm_path == /.*\// && norm_path != /\//)	# if it is not '/'
				norm_path = cut_tail(norm_path, 1);
			}

		var$norm_path = norm_path;

		var$abs_path = absolute_path(session, norm_path);

		var$base_path = subst(norm_path, /.*(\/+|\\+)/, "");
		# But ignore base path names that only contain whitespace and/or punctuations
		# if ( var$base_path == ftp_msg_field_separator )
		if ( var$base_path == "" )
			var$base_path = "~ none";

		# print ftp_anon_log, fmt("path=\"%s\", norm_path=\"%s\", abs_path = \"%s\", base_path=\"%s\"",
		# 			var$path, var$norm_path, var$abs_path, var$base_path);
		}

	return var;
	}


function strstr_clean(big: string, little: string, clean_match: bool): count
	{
	local i = strstr(big, little);

	if ( i == 0 ) return i;

	if ( clean_match )
		{
		local prefix = sub_bytes(big, 1, i - 1);
		local suffix = sub_bytes(big, i + byte_len(little), -1);

		# print ftp_anon_log, fmt("prefix = \"%s\", suffix = \"%s\"", prefix, suffix);
		# if little is not surrounded by blanks or punctuations
		if ( prefix != /|.*[[:blank:][:punct:]]/ ||
		     suffix != /|[[:blank:][:punct:]].*/ )
			return 0;
		}

	return i;
	}


# Search s for an argument variant. Note that variants are searched in
# the order of priorities -- the more specific the varient is, the
# higher priority it gets.

type arg_in_msg: record {
	arg: string;
	arg_ind: count;
	arg_len: count;
	prefix: string;
	suffix: string;
};

function check_arg_variant(s: string, arg: string, v: arg_in_msg, clean_match: bool): bool
	{
	if ( arg == "" || arg == "~ none" )
		return F;

	local i =  strstr_clean(s, arg, clean_match);
	if ( i <= 0 ) return F;

	local len = byte_len(arg);
	if ( len <= v$arg_len ) return F;

	v$arg = arg;
	v$arg_ind = i;
	v$arg_len = len;
	v$prefix = sub_bytes(s, 1, i - 1);
	v$suffix = sub_bytes(s, i + len, -1);
	return T;
	}

function expand_path_arg(v: arg_in_msg): bool
	{
	if ( v$prefix != /.*\// ) return F;

	local parts = split_all(v$prefix, /([^[:blank:][:punct:]]*\/)+/);
	local num_parts = length(parts);
	if ( parts[num_parts] != "" ) return F;
	local last_part = int_to_count(num_parts - 1);
	local s = parts[last_part];
	local s_len = byte_len(s);

	print ftp_anon_log, fmt("expand_path_arg: \"%s\" + \"%s\"", s, v$arg);
	v$arg_len = v$arg_len + s_len;
	v$arg_ind = int_to_count(v$arg_ind - s_len);
	v$arg = string_cat(s, v$arg);

	parts[last_part] = "";
	v$prefix = cat_string_array(parts);
	return T;
	}

function search_arg_variant(s: string, var: ftp_arg_variants, clean_match: bool): string
	{
	local v = [$arg = "", $arg_ind = 0, $arg_len = 0, $prefix = "", $suffix = ""];

	check_arg_variant(s, var$arg, v, clean_match);
	check_arg_variant(s, var$path, v, clean_match);
	check_arg_variant(s, var$norm_path, v, clean_match);
	check_arg_variant(s, var$abs_path, v, clean_match);
	check_arg_variant(s, var$base_path, v, clean_match);

	if ( var$path != "~ none" )
		expand_path_arg(v);

	return ( v$arg != "" ) ? v$arg : "~ none";
	}


# Substitute <arg> with a unique id in <msg>, store the mapping from
# the id to <arg> in <subst_map>, and update <other_pat> and <aux_pat>
# about the argument.
#
# It returns the message after substituion.

function process_arg_in_reply(arg_var: ftp_arg_variants, msg: string,
		other_pat: table[string] of string, aux_pat: set[string],
		subst_map: table[string] of string): string
	{
	add aux_pat[string_cat("~ arg", " : ", arg_var$arg)];
	add aux_pat[string_cat("~ arg", " : ", arg_var$path)];
	add aux_pat[string_cat("~ arg", " : ", arg_var$abs_path)];
	add aux_pat[string_cat("~ arg", " : ", arg_var$norm_path)];
	add aux_pat[string_cat("~ arg", " : ", arg_var$base_path)];

	local arg = search_arg_variant(msg, arg_var, T);
	if ( arg != "~ none" )
		{
		print ftp_anon_log, fmt("arg_variant_found: \"%s\" in \"%s\"", arg, msg);

		if ( arg != "" )
			{
			other_pat[arg] = "~ arg";
			if ( ftp_msg_field_separator in arg && arg != ftp_msg_field_separator )
				msg = subst_part(msg, arg, "", subst_map);
			}
		}

	return msg;
	}


# Record the message being stripped out

function strip_out_message(session: ftp_session_info, code: count, msg: string): string
	{
	local ind = fmt("%d %s", code, msg);
	if ( ind !in msg_stripped_out )
		{
		print ftp_anon_log,
			fmt("message_stripped_out: %s", msg);
		add msg_stripped_out[ind];
		}
	return "<message stripped out>";
	}


type msg_component: record {
	msg: pattern;
	part: pattern;
	context: pattern;
};

global msg_components_not_to_split: table[string] of msg_component;

event bro_init()
{
	# quoted string
	msg_components_not_to_split["quoted"] =
		[$msg = /.*/,
		 $part = /([^"]|\"\")*/,
		 $context = /@@BOL@@ *\"([^"]|\"\")*\"/];

	# port numbers in reply to PASV
	msg_components_not_to_split["port"] =
		[$msg = /227 .*/,
		 $part = /[0-9]+([[:blank:]]*,[[:blank:]]*[0-9]+){5}/,
		 $context = /\([0-9]+([[:blank:]]*,[[:blank:]]*[0-9]+){5}\)/];

	# dotted IP address
	msg_components_not_to_split["ip"] =
		[$msg = /.*/,	# any reply code
		 $part = /[0-9]{1,3}(\.[0-9]{1,3}){3}/,
		 $context = /[[:space:]\(\[][0-9]{1,3}(\.[0-9]{1,3}){3}[[:space:][:punct:]]/];

	# email
	msg_components_not_to_split["email"] =
		[$msg = /.*/,	# any reply code
		 $part = /[[:alnum:]\-\._]+@([\-0-9a-zA-Z]+\.)*[\-0-9a-zA-Z]+/,
		 $context = /[[:space:]\(\[<][[:alnum:]\-\.\_]+@([\-[:alnum:]]+\.)*[\-[:alnum:]]+[[:space:][:punct:]]/];

	# URL
	msg_components_not_to_split["url"] =
		[$msg = /.*/,	# any reply code
		 $part = /(http|ftp):\/\/[[:alnum:][:punct:]]+/,
		 $context = /(http|ftp):\/\/[[:alnum:][:punct:]]+/];

	# domain name
	msg_components_not_to_split["domain-version-filename"] =
		[$msg = /.*/,	# any reply code
		 $part = /([[:alnum:]]+[\-\.\_])+[[:alnum:]]+/,
		 $context = /[^\@\.\-\_[:alnum:]]([[:alnum:]]+[\-\.\_])+[[:alnum:]]+[[:space:][:punct:]]/];	# not proceeded by '@' (as in email)

	# UNIX file mode string
	msg_components_not_to_split["file_mode"] =
		[$msg = /(211|213) .*/,
		 $part = /[ld\-]([r-][w-][xs-]){3}/,
		 $context = /@@BOL@@ [[:blank:]]*[ld\-]([r\-][w\-][xs\-]){3}/];

	# file name in `ls -l`
	msg_components_not_to_split["ls_l_file_name"] =
		[$msg = /(211|213) @@BOL@@ [[:blank:]]*[ld\-]([r\-][w\-][xs\-]){3} .*/,
		 $part = /[^[:blank:]]+/,
		 $context = /[[:blank:]][^[:blank:]]+ @@EOL@@/];

	# symbolic links in `ls -l`
	msg_components_not_to_split["ls_l_symbolic_link"] =
		[$msg = /(211|213) @@BOL@@ [[:blank:]]*[ld\-]([r-][w-][xs-]){3} .*/,
		 $part = /[^[:blank:]]+/,
		 $context = /[[:blank:]][^[:blank:]]+ -> /];

	# time
	msg_components_not_to_split["time"] =
		[$msg = /.*/,	# any reply code
		 $part = /[0-9]{2}:[0-9]{2}(:[0-9]{2})?(am|pm)?/,
		 $context = /[[:space:]\(\[][0-9]{2}:[0-9]{2}(:[0-9]{2})?(am|pm)?[[:space:][:punct:]]/];
}

function subst_in_context(msg: string, orig_msg: string, c: msg_component, subst_map: table[string] of string): string
	{
	# print ftp_anon_log, fmt("msg = \"%s\", context = %s", msg, c$context);

	if ( orig_msg != c$msg || c$context !in msg )
		return msg;

	local parts = split_all(msg, c$context);
	local msg0 = msg;

	for ( i in parts )
		{
		# print ftp_anon_log, fmt("part[%d] = \"%s\"", i, parts[i]);
		if ( i % 2 == 0 )
			{
			local s = parts[i];
			local t = split_all(s, c$part);

			if ( length(t) > 1 && /X[[:alnum:]]{32}X/ !in t[2] )
				{
				# print ftp_anon_log, fmt("\"%s\" -> \"%s\" + \"%s\" + \"%s\"",
				#	to_string_literal(parts[i]), t[1], t[2], t[3]);
				# print ftp_anon_log, fmt("subst_in_context: \"%s\" [%s].[%s]",
				#	to_string_literal(s), c$part, c$context);

				local id = get_unique_subst_id(msg0, msg0);
				msg0 = string_cat(msg0, id);
				subst_map[id] =	t[2];
				t[2] = id;
				parts[i] = cat_string_array(t);
				# print ftp_anon_log, fmt("subst_in_context: \"%s\"->\"%s\" in \"%s\"",
				#	subst_map[id], id, to_string_literal(parts[i]));
				}
			}
		}

	return cat_string_array(parts);
	}


# The main function for FTP reply anonymization.  cmd_arg is the
# corresponding FTP request.

function anonymize_ftp_reply_by_msg_pattern(code: count, act_msg: string,
			cmd_arg: ftp_cmd_arg, session: ftp_session_info): string
	{
	local cmd = cmd_arg$cmd;
	local arg = cmd_arg$arg;
	local arg_var = expand_ftp_arg_variants(session, cmd_arg);

	# First check if trace-specific anonymization applies to the message
	if ( trace_specific_reply_anonymization )
		{
		local ret = anonymize_trace_specific_reply(session, code, act_msg, cmd_arg, arg_var);
		if ( ret$anonymized )
			{
			print ftp_anon_log, fmt("trace_specific_reply: %d \"%s\" ->\"%s\"",
				code, to_string_literal(act_msg), to_string_literal(ret$msg));
			return ret$msg;
			}
		}

	# Extract any prefix of form "<reply code>-"
	local prefix = "";
	local msg0 = act_msg;

	if ( code > 0 )
		{
		prefix = fmt("%d-", code);
		if ( strstr(msg0, prefix) == 1 ) # msg0 starts with prefix like '220-'
			msg0 = sub_bytes(msg0, byte_len(prefix) + 1, -1);
		else
			prefix = "";
		}


	# Below we will split the message into fields. However, before
	# the split we will first substitute certain substrings of the
	# message with unique ID's and switch the ID's back to the
	# corresponding strings after the split.

	# This is necessary to keep some part of the message from
	# being splitted, for instance, we'd like to split the
	# message:
	#
	# "'CWD /My Document/music/' command successful."
	#
	# with "/My Document/music/" as a single field instead two
	# fields: "/My" and "Document/music/".

	# Mark the two ends of the message
	msg0 = string_cat("@@BOL@@ ", msg0, " @@EOL@@");

	# For pattern extraction -- used by extract_ftp_reply_pattern
	local other_pat: table[string] of string;

	# For pattern matching -- used by match_pattern_part
	local aux_pat: set[string];

	local subst_map: table[string] of string;

	local orig_msg = fmt("%d %s", code, msg0);
	local msg1 = msg0;

	msg1 = subst_in_context(msg1, orig_msg, msg_components_not_to_split["file_mode"], subst_map);
	msg1 = subst_in_context(msg1, orig_msg, msg_components_not_to_split["ls_l_file_name"], subst_map);
	msg1 = subst_in_context(msg1, orig_msg, msg_components_not_to_split["ls_l_symbolic_link"], subst_map);

	# Process command in the reply message
	if ( cmd != "<missing>" )
		{
		other_pat[cmd] = "~ cmd";
		add aux_pat[string_cat("~ cmd", " : ", cmd)];
		add aux_pat[string_cat("~ cmd", " : ", to_lower(cmd))];
		if ( ftp_msg_field_separator in cmd )
			msg1 = subst_part(msg1, cmd, "", subst_map);
		}

	# Process arguments in reply. Note that the order is
	# critical: the argument variants are processed starting from
	# the most specific one.
	msg1 = process_arg_in_reply(arg_var, msg1, other_pat, aux_pat, subst_map);

	# Process directory in the reply
	local dir = "~ none";	# any directory contained in the reply
	if ( code == 257 || [cmd, code] in ftp_dir_operation )
		{
		dir = extract_dir_from_reply(session, msg1, dir);
		if ( dir != "~ none" )
			{
			other_pat[dir] = "~ dir";
			add aux_pat[string_cat("~ dir", " : ", dir)];
			if ( ftp_msg_field_separator in dir )
				msg1 = subst_part(msg1, dir, "", subst_map);
			}
		}

	# msg1 = subst_in_context(msg1, orig_msg, msg_components_not_to_split["quoted"], subst_map);
	msg1 = subst_in_context(msg1, orig_msg, msg_components_not_to_split["port"], subst_map);
	msg1 = subst_in_context(msg1, orig_msg, msg_components_not_to_split["email"], subst_map);
	msg1 = subst_in_context(msg1, orig_msg, msg_components_not_to_split["url"], subst_map);
	msg1 = subst_in_context(msg1, orig_msg, msg_components_not_to_split["ip"], subst_map);
	msg1 = subst_in_context(msg1, orig_msg, msg_components_not_to_split["domain-version-filename"], subst_map);
	msg1 = subst_in_context(msg1, orig_msg, msg_components_not_to_split["time"], subst_map);

	# Summarize all the substitution for debugging and verification
	local subst_str = "";
	if ( length(subst_map) > 0 )
		{
		for ( xx in subst_map )
			{
			if ( subst_str != "" )
				subst_str = string_cat(subst_str, ", ");
			subst_str = string_cat(subst_str, fmt("(\"%s\"->\"%s\")", to_string_literal(subst_map[xx]), xx));
			}
		print ftp_anon_log, fmt("substitute: \"%d %s\" with {%s}",
			code, act_msg, subst_str);
		}

	# Split the message to parts
	local msg_parts = split_all(msg1, ftp_msg_field_separator);
	local num_parts = length(msg_parts);

	# According to subst_map, change substitution ID's back to the
	# corresponding parts. Note that here we only look at whole
	# fields to look for substitution ID's.
	for ( i in msg_parts )
		{
		local this_part = msg_parts[i];
		if ( this_part in subst_map )
			{
			msg_parts[i] = subst_map[this_part];
			# print ftp_anon_log, fmt("substitute_part: \"%s\"", to_string_literal(msg_parts[i]));
			}
		}

	# Sanity check for string substitution
	local msg2 = cat_string_array(msg_parts);
	# msg2 != msg0 suggests that there is an improper substitution
	if ( msg2 != msg0 )
		{
		print ftp_anon_log, fmt("ERROR: substitution: \"%s\" -> \"%s\" with {%s} in [%s]",
			to_string_literal(msg0), to_string_literal(msg2),
			subst_str, id_string(session$connection_id));
		return strip_out_message(session, code, act_msg);
		}

	# So far the message is successfully splitted. Now we will try
	# to find a matching pattern.

	# Look it up in message patterns.
	local ind = fmt("%3d %3d", code, num_parts);

	if ( ind !in msg_pattern_groups )
		{
		print ftp_anon_log, fmt("pattern_not_found: \"%d %s\" in [%s]",
			code, act_msg, id_string(session$connection_id));
		extract_ftp_reply_pattern(code, act_msg, msg_parts, other_pat, session);
		return strip_out_message(session, code, act_msg);
		}

	local pat_group = msg_pattern_groups[ind];

	# There can be more than one matches ... record all of them
	# and pick the most promising one.
	local matches: table[string] of msg_pattern_match_result;
	local the_pat: msg_pattern_match_result;	# the best match
	the_pat$valid = F;

	for ( pat_str in pat_group )
		{
		local msg_pat = pat_group[pat_str];
		local tok: string_array;
		local r = do_msg_pattern_match(act_msg, msg_parts, msg_pat, aux_pat);
		if ( r$valid )
			{
			if ( length(matches) == 0 || cmp_msg_pattern_match(r, the_pat) < 0 )
				the_pat = r;
			matches[pat_str] = r;
			}
		}

	if ( length(matches) == 0 )
		{
		print ftp_anon_log, fmt("pattern_not_found: \"%d %s\" in [%s]",
			code, act_msg, id_string(session$connection_id));

		extract_ftp_reply_pattern(code, act_msg, msg_parts, other_pat, session);

		return strip_out_message(session, code, act_msg);
		}

	if ( length(matches) > 1 )
		print ftp_anon_log, fmt("multiple_patterns: \"%d %s\"", code, act_msg);

	print ftp_anon_log, fmt("message_matched: (%d) \"%d %s\" ~ \"%s\"",
					length(matches), code, act_msg, the_pat$pat$str);

	++the_pat$pat$hit;

	# Now we anonymize the message according to the_pat. During
	# the process we log two kinds of anonymization for manual
	# inspection:
	# 1) when a field matches the wild card pattern ('~ *'): this
	# will help us find information that is over-conservatively
	# anonymized;
	# 2) when a field matches a pattern with a 'to expose' flag (a
	# '+' at the end): this will help us to verify that the
	# exposed data is privacy-safe.

	local anon_parts: string_array;
	local match_wildcard = "";
	local match_exposure = "";

	for ( i in msg_parts )
		{
		local data = msg_parts[i];
		if ( i <= 2 || i >= num_parts - 1 )
			anon_parts[i] = subst(data, /@@BOL@@ | @@EOL@@/, "");
		else if ( i % 2 == 0 )
			anon_parts[i] = data;
		else
			{
			local p = the_pat$parts[int_to_count((i-1)/2)];
			anon_parts[i] = ( p != /~ .*/ ) ? data :
						anonymize_msg_part(data, p,
							cmd_arg, session);

			if ( p == /~ .+[+]/ )
				{
				if ( match_exposure != "" ) match_exposure = string_cat(match_exposure, "; ");
				match_exposure = string_cat(match_exposure, data);
				}

			if ( p == "~ *" )
				{
				if ( match_wildcard != "" ) match_wildcard = string_cat(match_wildcard, "; ");
				match_wildcard = string_cat(match_wildcard, data);
				}
			}
		}

	if ( match_wildcard != "" && [match_wildcard, the_pat$pat$str] !in all_wildcard_matches )
		{
		add all_wildcard_matches[match_wildcard, the_pat$pat$str];
		print ftp_anon_log, fmt("wildcard_match: in pattern: \"%s\" data: [%s] in [%s]",
			the_pat$pat$str,
			match_wildcard,
			id_string(session$connection_id));
		}

	if ( match_exposure != "" )
		{
		print ftp_anon_log, fmt("data_exposure: in pattern: \"%s\" data: [%s] in [%s]",
			the_pat$pat$str,
			match_exposure,
			id_string(session$connection_id));
		}

	local result = cat_string_array(anon_parts);

	# Stick the prefix back to the message.
	if ( prefix != "" )
		result = string_cat(prefix, result);

	return result;
	}
