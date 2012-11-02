@load ./main

module Auth;

export {
	## Authentication files that will be read off disk.
	## These files are meant to be continually appended and 
	## read in realtime.  If the file needs to be erased
	## due to size, "echo > thefile.dat" works well.
	## The data will only be read by the manager on a cluster.
	const read_files: set[string] = {} &redef;
}

event Auth::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Auth::Info)
	{
	event Auth::login_seen(item);
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
			                  $mode=Input::STREAM,
			                  $name=cat("auth-", a_file),
			                  $fields=Auth::Info,
			                  $ev=Auth::read_entry]);
			}
		}
	}

