# $Id:$

# Logs evidence regarding the degree to which the packet capture process
# suffers from measurment loss.
#
# By default, only reports loss computed in terms of number of "gap events"
# (ACKs for a sequence number that's above a gap).  You can also get an
# estimate in terms of number of bytes missing; this however is sometimes
# heavily affected by miscomputations due to broken packets with incorrect
# sequence numbers.  (These packets also affect the first estimator, but
# only to a quite minor degree.)

@load notice

module CaptureLoss;

export {
	redef enum Notice += {
		CaptureLossReport,	# interval report
		CaptureLossSummary,	# end-of-run summary
	};

	# Whether to also report byte-weighted estimates.
	global report_byte_based_estimates = F &redef;

	# Whether to generate per-interval reports even if there
	# was no evidence of loss.
	global report_if_none = F &redef;

	# Whether to generate a summary even if there was no
	# evidence of loss.
	global summary_if_none = F &redef;
}


# Redefine this to be non-zero to get per-interval reports.
redef gap_report_freq = 0 sec;

event gap_report(dt: interval, info: gap_info)
	{
	if ( info$gap_events > 0 || report_if_none )
		{
		local msg = report_byte_based_estimates ?
			fmt("gap-dt=%.6f acks=%d bytes=%d gaps=%d gap-bytes=%d",
				dt, info$ack_events, info$ack_bytes,
				info$gap_events, info$gap_bytes) :
			fmt("gap-dt=%.6f acks=%d gaps=%d",
				dt, info$ack_events, info$gap_events);

		NOTICE([$note=CaptureLossReport, $msg=msg]);
		}
	}
 
event bro_done()
	{
	local g = get_gap_summary();

	local gap_rate =
		g$ack_events == 0 ? 0.0 :
			(1.0 * g$gap_events) / (1.0 * g$ack_events);
	local gap_bytes =
		g$ack_bytes == 0 ? 0.0 :
			(1.0 * g$gap_bytes) / (1.0 * g$ack_bytes);

	if ( gap_rate == 0.0 && gap_bytes == 0.0 && ! summary_if_none )
		return;

	local msg = report_byte_based_estimates ?
		fmt("estimated rate = %g / %g (events/bytes)",
			gap_rate, gap_bytes) :
		fmt("estimated rate = %g", gap_rate);

	NOTICE([$note=CaptureLossSummary, $msg=msg]);
	}
