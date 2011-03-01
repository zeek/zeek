# $Id: print-filter.bro 4506 2007-06-27 14:40:34Z vern $

module PrintFilter;

export {
	# If true, terminate Bro after printing the filter.
	const terminate_bro = T &redef;

	# If true, write to log file instead of stdout.
	const to_file = F &redef;
	}

event bro_init()
	{
	if ( to_file )
		{
		local f = open_log_file("pcap_filter");
		print f, build_default_pcap_filter();
		close(f);
		}
	else
		print build_default_pcap_filter();

	if ( terminate_bro )
		exit();
	}
