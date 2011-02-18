
module Log;

export {
	# Each stream gets a unique ID. This type will be extended by
	# other scripts.
	type Stream: enum {
	    Unknown,
		Info,
		Debug,
		};

	# The default writer to use if a filter does not specify
	# anything else.
	const default_writer = WRITER_CSV &redef;

	# A filter defining what to record.
	type Filter: record {
		# A name to reference this filter.
		name: string;

		# A predicate returning True if the filter wants a log entry
		# to be recorded. If not given, an implicit True is assumed
		# for all entries. The predicate receives one parameter:
		# an instance of the log's record type with the fields to be
		# logged.
		pred: function(log: any) &optional;
    	
		# A path for outputting everything matching this
		# filter. The path is either a string, or a function
		# called with a single ``ID`` argument and returning a string.
		#
		# The specific interpretation of the string is left to the
		# Writer, but if it's refering to a file, it's assumed that no
		# extension is given; the writer will add whatever is
		# appropiate.
		path: any &optional;
    	
		# A subset of column names to record. If not given, all
		# columns are recorded.
		select: set[string] &optional;
    	
		# An event that is raised whenever the filter is applied
		# to an entry. The event receives the same parameter
		# as the predicate. It will always be generated,
		# independent of what the predicate returns.
		ev: event(l: any) &optional;
    	
		# The writer to use.
		writer: Writer &default=default_writer;
		};
}
