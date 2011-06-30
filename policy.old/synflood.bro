# $Id: synflood.bro 4054 2007-03-05 21:45:58Z vern $

@load notice

redef enum Notice += {
	SynFloodStart,    # start of syn-flood against a certain victim
	SynFloodEnd,      # end of syn-flood against a certain victim
	SynFloodStatus,   # report of ongoing syn-flood
};

# We report a syn-flood if more than SYNFLOOD_THRESHOLD new connections
# have been reported within the last SYNFLOOD_INTERVAL for a certain IP.
# (We sample the conns by one out of SYNFLOOD_SAMPLE_RATE, so the attempt
# counter is an estimated value.). If a victim is identified, we install a
# filter via install_dst_filter and sample the packets targeting it by
# SYNFLOOD_VICTIM_SAMPLE_RATE.
#
# Ongoing syn-floods are reported every SYNFLOOD_REPORT_INTERVAL.

global SYNFLOOD_THRESHOLD = 15000 &redef;
global SYNFLOOD_INTERVAL = 60 secs &redef;
global SYNFLOOD_REPORT_INTERVAL = 1 mins &redef;

# Sample connections by one out of x.
global SYNFLOOD_SAMPLE_RATE = 100 &redef;

# Sample packets to known victims with probability x.
global SYNFLOOD_VICTIM_SAMPLE_RATE = 0.01 &redef;

global conn_attempts: table[addr] of count &default = 0;
global victim_attempts: table[addr,addr] of count
	&default = 0  &read_expire = 5mins;

# We remember up to this many number of sources per victim.
global max_sources = 100;
global current_victims: table[addr] of set[addr] &read_expire = 60mins;
global accumulated_conn_attempts: table[addr] of count &default = 0;

global sample_count = 0;
global interval_start: time = 0;

# Using new_connection() can be quite expensive but connection_attempt() has
# a rather large lag that may lead to detecting flood too late. Additionally,
# it does not cover UDP/ICMP traffic.
event new_connection(c: connection)
	{
	if ( c$id$resp_h in current_victims )
		{
		++conn_attempts[c$id$resp_h];

		local srcs = current_victims[c$id$resp_h];
		if ( length(srcs) < max_sources )
			add srcs[c$id$orig_h];
		return;
		}

	if ( ++sample_count % SYNFLOOD_SAMPLE_RATE == 0 )
		{
		local ip = c$id$resp_h;

		if ( ++conn_attempts[ip] * SYNFLOOD_SAMPLE_RATE >
		     SYNFLOOD_THRESHOLD )
			{
			NOTICE([$note=SynFloodStart, $src=ip,
				   $msg=fmt("start of syn-flood against %s; sampling packets now", ip)]);

			add current_victims[ip][c$id$orig_h];

			# Drop most packets to victim.
			install_dst_addr_filter(ip, 0,
					1 - SYNFLOOD_VICTIM_SAMPLE_RATE);
			# Drop all packets from victim.
			install_src_addr_filter(ip, 0, 1.0);
			}
		}
	}

event check_synflood()
	{
	for ( ip in current_victims )
		{
		accumulated_conn_attempts[ip] =
			accumulated_conn_attempts[ip] + conn_attempts[ip];

		if ( conn_attempts[ip] * (1 / SYNFLOOD_VICTIM_SAMPLE_RATE) <
		     SYNFLOOD_THRESHOLD )
			{
			NOTICE([$note=SynFloodEnd, $src=ip, $n=length(current_victims[ip]),
				   $msg=fmt("end of syn-flood against %s; stopping sampling",
					ip)]);

			delete current_victims[ip];
			uninstall_dst_addr_filter(ip);
			uninstall_src_addr_filter(ip);
			}
		}

	clear_table(conn_attempts);
	schedule SYNFLOOD_INTERVAL { check_synflood() };
	}

event report_synflood()
	{
	for ( ip in current_victims )
		{
		local est_num_conn = accumulated_conn_attempts[ip] *
					(1 / SYNFLOOD_VICTIM_SAMPLE_RATE);

		local interv: interval;

		if ( interval_start != 0 )
			interv = network_time() - interval_start;
		else
			interv = SYNFLOOD_INTERVAL;

		NOTICE([$note=SynFloodStatus, $src=ip, $n=length(current_victims[ip]),
			   $msg=fmt("syn-flood against %s; estimated %.0f connections in last %s",
				    ip, est_num_conn, interv)]);
		}

	clear_table(accumulated_conn_attempts);

	schedule SYNFLOOD_REPORT_INTERVAL { report_synflood() };
	interval_start = network_time();
	}

event bro_init()
	{
	schedule SYNFLOOD_INTERVAL { check_synflood() };
	schedule SYNFLOOD_REPORT_INTERVAL { report_synflood() };
	}
