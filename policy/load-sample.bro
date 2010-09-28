# $Id: load-sample.bro 1758 2005-11-22 00:58:10Z vern $

# A simple form of profiling based on sampling the work done per-packet.
# load_sample() is generated every load_sample_freq packets (roughly;
# it's randomized).  For each sampled packet, "samples" contains a set
# of the functions, event handlers, and their source files that were accessed
# during the processing of that packet, along with an estimate of the
# CPU cost of processing the packet and (currently broken) memory allocated/
# freed.

global sampled_count: table[string] of count &default = 0;
global sampled_CPU: table[string] of interval &default = 0 sec;
global sampled_mem: table[string] of int &default = +0;

global num_samples = 0;
global total_sampled_CPU = 0 sec;
global total_sampled_mem = +0;

event load_sample(samples: load_sample_info, CPU: interval, dmem: int)
	{
	++num_samples;
	total_sampled_CPU += CPU;
	total_sampled_mem += dmem;

	if ( |samples| == 0 )
		add samples["<nothing>"];

	for ( i in samples )
		{
		++sampled_count[i];
		sampled_CPU[i] += CPU;
		sampled_mem[i] += dmem;
		}
	}

event bro_done()
	{
	for ( i in sampled_CPU )
		print fmt("%s: %d%% pkts, %.1f%% CPU",
			i, sampled_count[i] * 100 / num_samples,
			sampled_CPU[i] * 100 / total_sampled_CPU);
			# sampled_mem[i] / total_sampled_mem;
	}
