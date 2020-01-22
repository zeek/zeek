// See the file "COPYING" in the main distribution directory for copyright.

#include "Options.h"

void zeek::Options::filter_supervisor_options()
	{
	pcap_filter = {};
	interfaces = {};
	pcap_files = {};
	signature_files = {};
	pcap_output_file = {};
	}

void zeek::Options::filter_supervised_node_options()
	{
	auto og = *this;
	*this = {};

	debug_log_streams = og.debug_log_streams;
	debug_script_tracing_file = og.debug_script_tracing_file;
	script_code_to_exec = og.script_code_to_exec;
	script_prefixes = og.script_prefixes;

	signature_re_level = og.signature_re_level;
	ignore_checksums = og.ignore_checksums;
	use_watchdog = og.use_watchdog;
	pseudo_realtime = og.pseudo_realtime;
	dns_mode = og.dns_mode;

	bare_mode = og.bare_mode;
	perftools_check_leaks = og.perftools_check_leaks;
	perftools_profile = og.perftools_profile;

	pcap_filter = og.pcap_filter;
	signature_files = og.signature_files;

	// TODO: These are likely to be handled in a node-specific or
	// use-case-specific way.  e.g. interfaces is already handled for the
	// "cluster" use-case, but don't have supervised-pcap-reading
	// functionality yet.
	/* interfaces = og.interfaces; */
	/* pcap_files = og.pcap_files; */

	pcap_output_file = og.pcap_output_file;
	random_seed_input_file = og.random_seed_input_file;
	random_seed_output_file = og.random_seed_output_file;
	process_status_file = og.process_status_file;

	plugins_to_load = og.plugins_to_load;
	scripts_to_load = og.scripts_to_load;
	script_options_to_set = og.script_options_to_set;
	}
