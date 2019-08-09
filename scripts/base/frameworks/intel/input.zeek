##! Input handling for the intelligence framework. This script implements the
##! import of intelligence data from files using the input framework.

@load ./main

module Intel;

export {
	## Intelligence files that will be read off disk. The files are
	## reread every time they are updated so updates must be atomic
	## with "mv" instead of writing the file in place.
	const read_files: set[string] = {} &redef;

	## An optional path prefix for intel files. This prefix can, but
	## need not be, absolute. The default is to leave any filenames
	## unchanged. This prefix has no effect if a read_file entry is
	## an absolute path. This prefix gets applied _before_ entering
	## the input framework, so if the prefix is absolute, the input
	## framework won't munge it further. If it is relative, then
	## any path_prefix specified in the input framework will apply
	## additionally.
	const path_prefix = "" &redef;

	## This event is raised each time the intel framework reads a new line
	## from an intel file. It is used in the intel framework but can
	## also be used in custom scripts for further checks.
	##
	## desc: The :zeek:type:`Input::EventDescription` record which generated the event.
	##
	## tpe: The type of input event.
	##
	## item: The intel item being read (of type :zeek:type:`Intel::Item`).
	##
	global read_entry: event(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item);

	## This event is raised each time the input framework detects an error
	## while reading the intel file. It can be used to implement further checks
	## in custom scripts. Errors can be of different levels (information, warning, errors).
	##
	## desc: The :zeek:type:`Input::EventDescription` record which generated the error.
	##
	## message: An error message.
	##
	## level: The :zeek:type:`Reporter::Level` of the error.
	##
	global read_error: event(desc: Input::EventDescription, message: string, level: Reporter::Level);
}

event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
	{
	Intel::insert(item);
	}

event zeek_init() &priority=5
	{
	if ( ! Cluster::is_enabled() ||
	     Cluster::local_node_type() == Cluster::MANAGER )
		{
		for ( a_file in read_files )
			{
			# Handle prefixing of the source file name. Note
			# that this currently always uses the ASCII reader,
			# so we know we're dealing with filenames.
			local source = a_file;

			# If we have a path prefix and the file doesn't
			# already have an absolute path, prepend the prefix.
			if ( |path_prefix| > 0 && sub_bytes(a_file, 0, 1) != "/" )
				source = cat(rstrip(path_prefix, "/"), "/", a_file);

			Input::add_event([$source=source,
			                  $reader=Input::READER_ASCII,
			                  $mode=Input::REREAD,
			                  $name=cat("intel-", a_file),
			                  $fields=Intel::Item,
			                  $ev=Intel::read_entry,
			                  $error_ev=Intel::read_error]);
			}
		}
	}

