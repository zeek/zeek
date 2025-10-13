global h: opaque of Broker::Store;

event zeek_init()
	{
	# Use WAL mode.
	local sqlite_options=Broker::SQLiteOptions(
		$synchronous=Broker::SQLITE_SYNCHRONOUS_NORMAL,
		$journal_mode=Broker::SQLITE_JOURNAL_MODE_WAL,
	);
	local options = Broker::BackendOptions($sqlite=sqlite_options);
	h = Broker::create_master("persistent-store", Broker::SQLITE, options);

	local c = 1000;
	while (c > 0)
		{
		Broker::put(h, cat(c), rand(10000));
		--c;
		}
	}
