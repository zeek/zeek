##! This script is to support the bpf.conf file like other network monitoring tools use.

@load base/frameworks/notice

module BPFConf;

export {
	## The file that is watched on disk for BPF filter changes.
	const filename = "" &redef;

	redef enum Notice::Type += { 
		## Invalid filter notice.
		InvalidFilter
	};
}

# This is used for temporary storage of lines from the file.
global filter_parts: vector of string = vector();


redef enum PcapFilterID += {
	BPFConfFilter,
};

# Record used in file reader event.
type FilterLine: record {
	s: string;
};

event BPFConf::line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local part = sub(s, /[[:blank:]]*#.*$/, "");

	# We don't want any blank parts.
	if ( part != "" )
		filter_parts[|filter_parts|] = part;
	}

event Input::end_of_data(name: string, source:string)
	{
	if ( name == "bpfconf" )
		{
		local filter = join_string_vec(filter_parts, " ");
		capture_filters["bpf.conf"] = filter;
		if ( precompile_pcap_filter(BPFConfFilter, filter) )
			{
			PacketFilter::install();
			}
		else
			{
			NOTICE([$note=InvalidFilter,
			        $msg=fmt("Compiling packet filter from %s failed", filename),
			        $sub=filter]);
			}

		filter_parts=vector();
		}
	}

event bro_init() &priority=5
	{
	if ( BPFConf::filename != "" )
		{
		Input::add_event([$source=BPFConf::filename,
		                  $name="bpfconf",
		                  $reader=Input::READER_RAW,
		                  $mode=Input::REREAD,
		                  $want_record=F,
		                  $fields=FilterLine,
		                  $ev=BPFConf::line]);
		}
	}