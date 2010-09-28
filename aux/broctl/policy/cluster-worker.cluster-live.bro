# $Id: cluster-worker.cluster-live.bro 6811 2009-07-06 20:41:10Z robin $
#
# Only loaded when running live, not when just checking configuration.

@load print-filter
	
redef PrintFilter::terminate_bro = F; 
redef PrintFilter::to_file = T; 
