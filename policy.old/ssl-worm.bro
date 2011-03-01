# $Id: ssl-worm.bro 340 2004-09-09 06:38:27Z vern $

@load signatures
@load software
@load alarm

redef signature_files += "ssl-worm.sig";

redef capture_filters +=  {
	["ssl-worm"] = "udp port 2002 and src net 134.96"
};

function sslworm_is_server_vulnerable(state: signature_state): bool
	{
	local ip = state$conn$id$resp_h;

	if ( ip !in software_table )
		return F;

	local softset = software_table[ip];

	if ( "Apache" !in softset )
		return F;

	if ( "OpenSSL" !in softset )
		return F;

	local safe_version: software_version =
		[$major = +0, $minor = +9, $minor2 = +6, $addl = "e"];

	if ( software_cmp_version(softset["OpenSSL"]$version, safe_version) >= 0 )
		return F;

	return T;
	}

function sslworm_has_server_been_probed(state: signature_state): bool
	{
	# FIXME: Bro segfaults without the tmp variable
	local result =
		has_signature_matched("sslworm-probe",
				state$conn$id$orig_h, state$conn$id$resp_h);

	return result;
	}

function sslworm_has_server_been_exploited(state: signature_state): bool
	{
	# FIXME: I don't know which side starts the UDP conversation
	local result =
		has_signature_matched("sslworm-exploit",
				state$conn$id$orig_h, state$conn$id$resp_h);

	if ( ! result )
		result = has_signature_matched("sslworm-exploit",
				state$conn$id$resp_h, state$conn$id$orig_h);

	return result;
	}
