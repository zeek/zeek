# $Id: trw.bro 2911 2006-05-06 17:58:43Z vern $

@load notice
@load port-name
@load hot

module TRW;

export {
	redef enum Notice += {
		TRWAddressScan,	# source flagged as scanner by TRW algorithm
		TRWScanSummary,	# summary of scanning activities reported by TRW
	};

	# Activate TRW if T.
	global use_TRW_algorithm = F &redef;

	# Tell TRW not to flag a friendly remote.
	global do_not_flag_friendly_remotes = T &redef;

	# Set of services for outbound connections that are possibly triggered
	# by incoming connections.
	const triggered_outbound_services = { ident, finger, 20/tcp, } &redef;

	# The following correspond to P_D and P_F in the TRW paper, i.e., the
	# desired detection and false positive probabilities.
	global target_detection_prob = 0.99 &redef;
	global target_false_positive_prob = 0.01 &redef;

	# Given a legitimate remote, the probability that its connection
	# attempt will succeed.
	global theta_zero = 0.8 &redef;

	# Given a scanner, the probability that its connection attempt
	# will succeed.
	global theta_one  = 0.2 &redef;


	# These variables the user usually won't alter, except they
	# might want to adjust the expiration times, which is why
	# they're exported here.
	global scan_sources: set[addr] &write_expire = 1 hr;
	global benign_sources: set[addr] &write_expire = 1 hr;

	global failed_locals: set[addr, addr] &write_expire = 30 mins;
	global successful_locals: set[addr, addr] &write_expire = 30 mins;

	global lambda: table[addr] of double
		&default = 1.0 &write_expire = 30 mins;
	global num_scanned_locals:
		table[addr] of count &default = 0 &write_expire = 30 mins;

	# Function called to perform TRW analysis.
	global check_TRW_scan: function(c: connection, state: string,
					reverse: bool): bool;
}

# Set of remote hosts that have been successfully accessed by local hosts.
global friendly_remotes: set[addr] &read_expire = 30 mins;

# Set of local honeypot hosts - for internal use at LBL.
global honeypot: set[addr];

# Approximate solutions for upper and lower thresholds.
global eta_zero: double;	# initialized when Bro starts
global eta_one: double;

event bro_init()
	{
	eta_zero =
		(1 - target_detection_prob) / (1 - target_false_positive_prob);
	eta_one = target_detection_prob / target_false_positive_prob;
	}


event TRW_scan_summary(orig: addr)
	{
	NOTICE([$note=TRWScanSummary, $src=orig,
		$msg=fmt("%s scanned a total of %d hosts",
		orig, num_scanned_locals[orig])]);
	}

function check_TRW_scan(c: connection, state: string, reverse: bool): bool
	{
	local id = c$id;

	local service = "ftp-data" in c$service ? 20/tcp
		: (reverse ? id$orig_p : id$resp_p);
	local orig = reverse ? id$resp_h : id$orig_h;
	local resp = reverse ? id$orig_h : id$resp_h;
	local outbound = is_local_addr(orig);

	# Mark a remote as friendly if it is successfully accessed by
	# a local with protocols other than triggered_outbound_services.
	# XXX There is an ambiguity to determine who initiated a
	# connection when the status is "OTH".
	if ( outbound )
		{
		if ( resp !in scan_sources &&
		     service !in triggered_outbound_services &&
		     orig !in honeypot && state != "OTH" )
			add friendly_remotes[resp];

		return F;
		}

	if ( orig in scan_sources )
		return T;

	if ( orig in benign_sources )
		return F;

	if ( do_not_flag_friendly_remotes && orig in friendly_remotes )
		return F;

	# Start TRW evaluation.
	local flag = +0;
	local resp_byte = reverse ? c$orig$size : c$resp$size;
	local established = T;

	if ( state == "S0" || state == "REJ" || state == "OTH" ||
	     (state == "RSTOS0" && resp_byte <= 0) )
		established = F;

	if ( ! established || resp in honeypot )
		{
		if ( [orig, resp] !in failed_locals )
			{
			flag = 1;
			add failed_locals[orig, resp];
			}
		}

	else if ( [orig, resp] !in successful_locals )
		{
		flag = -1;
		add successful_locals[orig, resp];
		}

	if ( flag == 0 )
		return F;

	local ratio = 1.0;

	# Update the corresponding likelihood ratio of orig.
	if ( theta_zero <= 0 || theta_zero >= 1 || theta_one <= 0 ||
	     theta_one >= 1 || theta_one >= theta_zero )
		{
		# Error: theta_zero should be between 0 and 1.
		alarm "bad theta_zero/theta_one in check_TRW_scan";
		use_TRW_algorithm = F;
		return F;
		}

	if ( flag == 1 )
		ratio = (1 - theta_one) / (1 - theta_zero);

	if ( flag == -1 )
		ratio = theta_one / theta_zero;

	++num_scanned_locals[orig];

	lambda[orig] = lambda[orig] * ratio;
	local updated_lambda = lambda[orig];

	if ( target_detection_prob <= 0 ||
	     target_detection_prob >= 1 ||
	     target_false_positive_prob <= 0 ||
	     target_false_positive_prob >= 1 )
		{
		# Error: target probabilities should be between 0 and 1
		alarm "bad target probabilities in check_TRW_scan";
		use_TRW_algorithm = F;
		return F;
		}

	if ( updated_lambda > eta_one )
		{
		add scan_sources[orig];
		NOTICE([$note=TRWAddressScan, $src=orig,
			$msg=fmt("%s scanned a total of %d hosts",
				orig, num_scanned_locals[orig])]);
		schedule 1 day { TRW_scan_summary(orig) };
		return T;
		}

	if ( updated_lambda < eta_zero )
		add benign_sources[orig];

	return F;
	}
