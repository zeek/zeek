@load ./main

module Intel;

export {
	## Intelligence files that will be read off disk.  The files are
	## reread every time they are updated so updates must be atomic with
	## "mv" instead of writing the file in place.
	const read_files: set[string] = {} &redef;
}

event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
	{
	Intel::insert(item);
	}

event bro_init() &priority=5
	{
	if ( ! Cluster::is_enabled() ||
	     Cluster::local_node_type() == Cluster::MANAGER )
		{
		for ( a_file in read_files )
			{
			Input::add_event([$source=a_file,
			                  $reader=Input::READER_ASCII,
			                  $mode=Input::REREAD,
			                  $name=cat("intel-", a_file),
			                  $fields=Intel::Item,
			                  $ev=Intel::read_entry]);
			}
		}
	}

