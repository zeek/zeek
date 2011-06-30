# const number_of_regions = 32;
const region_size = 1024 * 1024;	# 1MB
@load large-conns

global conn_size_log = open_log_file("conn-size") &redef;

function conn_id_string(id: conn_id): string
	{
	return fmt("%s/%d=>%s/%s",
		id$orig_h, id$orig_p,
		id$resp_h, id$resp_p);
	}

function report_size_error(c: connection, msg: string)
	{
	print conn_size_log, fmt("conn %s start %.6f duration %.6f pkt_^ %d pyld_^ %d pkt_v %d pyld_v %d size_error [%s]",
		conn_id_string(c$id),
		c$start_time,
		c$duration,
		c$orig$num_pkts, c$orig$size,
		c$resp$num_pkts, c$resp$size,
		msg);
	}

function conn_size(c: connection, is_orig: bool): string
	{
	local endp = is_orig ? c$orig : c$resp;
	local endp_name = is_orig ? "orig" : "resp";
	local size = endp$size;

	if ( is_tcp_port(c$id$resp_p) )
		# double check TCP sizes
		{
		local est = estimate_flow_size_and_remove(c$id, is_orig);
		if ( est$have_est )
			{
			print conn_size_log,
				fmt("conn %s endpoint %s size %d low %.0fMB high %.0fMB inconsistent %d",
					conn_id_string(c$id), endp_name,
					endp$size,
					est$lower / 1e6,
					est$upper / 1e6,
					est$num_inconsistent);

			if ( est$num_inconsistent > 0 )
				{
				report_size_error(c,
					fmt("%s size error inconsistent %d",
						endp_name,
						est$num_inconsistent));
				return "-";
				}

			if ( size < est$lower || size > est$upper )
				{
				report_size_error(c,
					fmt("%s size error estimates: %.0fMB - %.0fMB",
						endp_name,
						est$lower / 1e6,
						est$upper / 1e6));
				return "-";
				}
			}
		}
	else if ( is_udp_port(c$id$resp_p) )
		{
		if ( endp$num_pkts > size && size != 0 )
			{
			report_size_error(c,
				fmt("%s size error: pkt > size",
					endp_name));
			return "-";
			}
		}

	return fmt("%d", size);
	}

event connection_state_remove(c: connection)
	{
	local orig_size = conn_size(c, T);
	local resp_size = conn_size(c, F);
	}
