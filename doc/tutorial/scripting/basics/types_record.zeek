# This defines an asset with various fields, accessible with '$'
type Asset: record {
	ip: addr;
	owner: string;
	last_seen: time;
	is_public: bool;
};

event zeek_init()
	{
	# Create a new record instance
	local my_asset: Asset = Asset(
		$ip=192.168.1.50,
		$owner="Evan",
	    $last_seen=network_time(),
		$is_public=T,
	);

	# Access its is_public field with '$'
	if ( my_asset$is_public )
		{
		print fmt("%s's asset is public at %s", my_asset$owner, my_asset$ip);
		}

	# You can also change fields
	my_asset$is_public = F;
	if ( ! my_asset$is_public )
		{
		print fmt("%s's asset is not public anymore", my_asset$owner);
		}
	}
