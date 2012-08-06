@load ./main

module Intel;

export {
	## Files that will be read off disk
	const read_files: set[string] = {} &redef;

	global entry: event(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item);
}

event Intel::entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
	{
	Intel::insert(item);
	}

event bro_init() &priority=5
	{
	for ( a_file in read_files )
		{
		Input::add_event([$source=a_file,
		                  $reader=Input::READER_ASCII,
		                  $mode=Input::REREAD,
		                  $name=cat("intel-", a_file),
		                  $fields=Intel::Item,
		                  $ev=Intel::entry]);
		}
	}
