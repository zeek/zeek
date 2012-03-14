# TCP connection processing.

module TCP_Perf;

# log level.  either:
# 1. Summaries - only summaries (e.g., RTT summary for a connection)
# 2. InterestingEvents - summaries, as well as when interesting things
#    happen (e.g., window size hits a new max)
# 3. All - absolutely everything.  will output things per packet, in
#    general.  i only recommend this for debugging, or if you need to
#    track something (probably RTT or flight size) over time

# this is a little annoying at the moment.  comment out the ones you
# don't want.  if you want log_lev_interesting, e.g., comment out
# log_lev_all.  DON'T also comment out log_lev_summary

global log_lev_all = T;
global log_lev_interesting = T;
global log_lev_summary = T;

# these redefs have now replaced the "log_rtt", etc., variables.
# ignoring a particular type of event will prevent any of those events
# from getting thrown in BRO, so there is not a need to use @ifdefs
# for that purposes here.

# NB1: setting ignore_window_events to T is enough to get large traces
# to run without running out of memory.  this is a temporary fix.

# NB2: setting the other two to false does *not* save state.  this is
# because the state for rtt events and tcp events is conflated.
#
# TODO: separate them, or at least save state if both are true

#redef ignore_window_events = T;
#redef ignore_tcp_events = T;
#redef ignore_rtt_events = T;

# for RTT analysis, we're interested in more than just SYNs and FINs;
# we want all TCP packets.  so don't do ["tcp"] = "tcp[13] & 7 != 0"
#redef capture_filters += { ["tcp perf"] = "tcp" };

# new log file
const log_file = open_log_file("tcp-anomalies");

# returns a string representing a connection ("src_h:src_p dst_h:dst_p")
function connection_string(c: connection): string
{
		local orig_host = c$id$orig_h;
		local orig_port = c$id$orig_p;
		local resp_host = c$id$resp_h;
		local resp_port = c$id$resp_p;

		local c_string = fmt("%s:%d %s:%d", orig_host, orig_port, resp_host, resp_port);

		return c_string;
}

######################################################################
# events start here

# ------------------------------ RTT events

@ifdef (log_lev_all)
# RTT estimate made (this is potentially expensive -- it's thrown every time an RTT estimate is made)
event conn_rtt(c: connection, timestamp: double, rtt: double, seq: count, packet_size: int, is_syn: bool, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f rtt_estimate %s rtt=%f seq=%d packet_size=%d is_syn=%d is_orig=%d", timestamp, s, rtt, seq, packet_size, is_syn, is_orig);

		print log_file, log_str;
}
@endif

@ifdef (log_lev_interesting)
# rtt = ack time - syn time
#
# NOTE: the time for the syn will be the time of the *last* syn; the
# time for the ack will be the time of the *first* ack (in the case of
# retransmissions)

event tcp_handshake_sa_estimate(c: connection, timestamp: double, rtt: double, syn_size: count, syn_ack_size: count)
{
		local s = connection_string(c);
		print log_file, fmt("%f handshake_sa_estimate %s rtt=%f syn_size=%d syn_ack_size=%d", timestamp, s, rtt, syn_size, syn_ack_size);
}

# rtt1 = diff between syn and syn-ack
# rtt2 = diff between syn-ack and ack
# rtt = rtt1 + rtt2
#
# if there are no retransmissions, this method gives the same rtt
# estimate as the above.  in the case of retransmissions with the
# syn-ack, its rtt estimate will be smaller (and likely more accurate)
#
# note that the above only requires unidirectional traffic, though.

event tcp_handshake_sum_estimate(c: connection, timestamp: double, rtt: double, rtt1: double, rtt2: double, syn_size: count, syn_ack_size: count)
{
		local s = connection_string(c);
		print log_file, fmt("%f handshake_sum_estimate %s rtt=%f rtt1=%f rtt2=%f syn_size=%d syn_ack_size=%d", timestamp, s, rtt, rtt1, rtt2, syn_size, syn_ack_size);
}
@endif

# connection closed - RTT summary
#
# timestamp is the time the connection was closed (when Done() was called)
@ifdef (log_lev_summary)
event conn_rtt_summary(c: connection, timestamp: double, stats: rtt_stats, is_src: bool)
{
		local min_rtt = stats$min;
		local max_rtt = stats$max;
		local mean_rtt = stats$mean;
		local median_rtt = stats$median;
		local q1_rtt = stats$lower_quartile;
		local q3_rtt = stats$upper_quartile;

		local min_rtt_time = stats$min_time;
		local max_rtt_time = stats$max_time;

		local s = connection_string(c);
		
		local location = "src";
		if (!is_src) {
		   location = "dst";
		}

		local log_str_1 = fmt("%f rtt_summary %s min_rtt=%f min_rtt_time=%f max_rtt=%f max_rtt_time=%f", timestamp, s, min_rtt, min_rtt_time, max_rtt, max_rtt_time);
		local log_str_2 = fmt("%f rtt_summary %s mean_rtt=%f median_rtt=%f q1_rtt=%f q3_rtt=%f", timestamp, s, mean_rtt, median_rtt, q1_rtt, q3_rtt);
		local log_str_3 = fmt("%f rtt_summary %s measurement_location=%s", timestamp, s, location);

		print log_file, log_str_1;	   
		print log_file, log_str_2;
		print log_file, log_str_3;
}

# this is almost the same as the previous summary, but it gets thrown
# by the "wrong" endpoint (the one farther from the measurement_location), so
# it will report extremely small RTTs.  this is for research
# purposes, not so much for an actual Bro release (which is, in part,
# one of the reasons why i'm making this a separate event)
event conn_secondary_rtt_summary(c: connection, timestamp: double, stats: rtt_stats)
{
		local min_rtt = stats$min;
		local max_rtt = stats$max;
		local mean_rtt = stats$mean;
		local median_rtt = stats$median;
		local q1_rtt = stats$lower_quartile;
		local q3_rtt = stats$upper_quartile;

		local min_rtt_time = stats$min_time;
		local max_rtt_time = stats$max_time;

		local s = connection_string(c);
		
		local log_str_1 = fmt("%f secondary_rtt_summary %s min_rtt=%f min_rtt_time=%f max_rtt=%f max_rtt_time=%f", timestamp, s, min_rtt, min_rtt_time, max_rtt, max_rtt_time);
		local log_str_2 = fmt("%f secondary_rtt_summary %s mean_rtt=%f median_rtt=%f q1_rtt=%f q3_rtt=%f", timestamp, s, mean_rtt, median_rtt, q1_rtt, q3_rtt);

		print log_file, log_str_1;	   
		print log_file, log_str_2;
}

@endif

#------------------------------ Window events

@ifdef (log_lev_all)
event tcp_data_in_flight(c: connection, timestamp: double, bytes: int, packets: int, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f data_in_flight %s bytes=%d packets=%d is_orig=%d", timestamp, s, bytes, packets, is_orig);

		print log_file, log_str;
}
@endif

@ifdef (log_lev_interesting)
event tcp_new_flight_max(c: connection, timestamp: double, max: int, prev_max: int, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f new_flight_max %s max=%d prev_max=%d is_orig=%d", timestamp, s, max, prev_max, is_orig);

		print log_file, log_str;
}

event tcp_window_limited(c: connection, timestamp: double, window: int, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f window_limited %s window=%d is_orig=%d", timestamp, s, window, is_orig);

		print log_file, log_str;
}

event tcp_small_window(c: connection, timestamp: double, window: int, mss: int, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f small_window %s window=%d mss=%d is_orig=%d", timestamp, s, window, mss, is_orig);

		print log_file, log_str;
}

event tcp_zero_window(c: connection, timestamp: double, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f zero_window %s is_orig=%d", timestamp, s, is_orig);

		print log_file, log_str;
}

event tcp_window_probe(c: connection, timestamp: double, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f window_probe %s is_orig=%d", timestamp, s, is_orig);

		print log_file, log_str;
}
@endif

@ifdef (log_lev_summary)
event conn_window_summary(c: connection, timestamp: double, orig_stats: window_stats, resp_stats: window_stats)
{
		local s = connection_string(c);

		local o_min = orig_stats$min;
		local o_max = orig_stats$max;
		local o_med = orig_stats$median;

		local r_min = resp_stats$min;
		local r_max = resp_stats$max;
		local r_med = resp_stats$median;

		local log_str_1 = fmt("%f orig_window_summary %s median=%d min=%d max=%d", timestamp, s, o_med, o_min, o_max);
		local log_str_2 = fmt("%f resp_window_summary %s median=%d min=%d max=%d", timestamp, s, r_med, r_min, r_max);

		print log_file, log_str_1;
		print log_file, log_str_2;
}

event conn_flight_size_summary(c: connection, timestamp: double, orig_stats: flight_stats, resp_stats: flight_stats)
{
		local s = connection_string(c);

		local o_mean = orig_stats$mean;
		local o_med = orig_stats$median;
		local o_q1 = orig_stats$lower_quartile;
		local o_q3 = orig_stats$upper_quartile;
		local o_min = orig_stats$min;
		local o_max = orig_stats$max;

		local r_mean = resp_stats$mean;
		local r_med = resp_stats$median;
		local r_q1 = resp_stats$lower_quartile;
		local r_q3 = resp_stats$upper_quartile;
		local r_min = resp_stats$min;
		local r_max = resp_stats$max;

		local log_str_1 = fmt("%f orig_flight_size_summary %s mean=%f median=%d q1=%d q3=%d min=%d max=%d", timestamp, s, o_mean, o_med, o_q1, o_q3, o_min, o_max);
		local log_str_2 = fmt("%f resp_flight_size_summary %s mean=%f median=%d q1=%d q3=%d min=%d max=%d", timestamp, s, r_mean, r_med, r_q1, r_q3, r_min, r_max);

		print log_file, log_str_1;
		print log_file, log_str_2;
}

@endif

#------------------------------ TCP events

@ifdef (log_lev_interesting)
# packet was retransmitted
#
# timestamp is the timestamp of the retransmission.  (timestamp - delay_time is then the time of the original packet)
event tcp_retransmission(c: connection, timestamp: double, seq: count, delay_time: double, is_orig: bool, is_syn: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f packet_retransmission %s rtx_seq=%d delay_time=%f is_orig=%d is_syn=%d", timestamp, s, seq, delay_time, is_orig, is_syn);

		print log_file, log_str;
}

event tcp_out_of_order(c: connection, timestamp: double, seq: count, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f out_of_order %s seq=%d is_orig=%d", timestamp, s, seq, is_orig);

		print log_file, log_str;
}

event tcp_ack_above_gap(c: connection, timestamp: double, ack_seq: count, gap_min: count, gap_max: count, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f ack_above_gap %s ack_seq=%d gap_min=%d gap_max=%d is_orig=%d", timestamp, s, ack_seq, gap_min, gap_max, is_orig);

		print log_file, log_str;
}

event tcp_replay(c: connection, timestamp: double, seq: count, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f replay %s seq=%d is_orig=%d", timestamp, s, seq, is_orig);

		print log_file, log_str;
}

event tcp_bad_checksum(c: connection, timestamp: double, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f bad_checksum %s is_orig=%d", timestamp, s, is_orig);

		print log_file, log_str;
}

event tcp_outstanding_data(c: connection, timestamp: double, bytes: int, is_orig: bool)
{
		local s = connection_string(c);
		local log_str = fmt("%f outstanding_data %s bytes=%d is_orig=%d", timestamp, s, bytes, is_orig);

		print log_file, log_str;
}
@endif

@ifdef (log_lev_summary)
event conn_stats(c: connection, timestamp: double, os: endpoint_stats, rs: endpoint_stats)
{
		local s = connection_string(c);

		local o_num_pkts = os$num_pkts;
		local o_num_rxmit = os$num_rxmit;
		local o_num_rxmit_bytes = os$num_rxmit_bytes;
		local o_num_OO = os$num_OO;
		local o_num_repl = os$num_repl;

		local r_num_pkts = rs$num_pkts;
		local r_num_rxmit = rs$num_rxmit;
		local r_num_rxmit_bytes = rs$num_rxmit_bytes;
		local r_num_OO = rs$num_OO;
		local r_num_repl = rs$num_repl;

		# there are also fields for gap events and max flight sizes, but i don't want to print them

		local log_str_1 = fmt("%f orig_conn_summary %s num_pkts=%d num_rx=%d num_rx_bytes=%d num_OO=%d num_repl=%d", timestamp, s, o_num_pkts, o_num_rxmit, o_num_rxmit_bytes, o_num_OO, o_num_repl);
		local log_str_2 = fmt("%f resp_conn_summary %s num_pkts=%d num_rx=%d num_rx_bytes=%d num_OO=%d num_repl=%d", timestamp, s, r_num_pkts, r_num_rxmit, r_num_rxmit_bytes, r_num_OO, r_num_repl);

		print log_file, log_str_1;
		print log_file, log_str_2;
}
@endif