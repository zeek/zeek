event zeek_init()
	{
	# Create a table that maps addresses (the key) to a string (value)
	local asset_names: table[addr] of string = table(
		[192.168.1.1] = "Router",
		[8.8.8.8] = "Google DNS"
	);

	# Add or replace elements with an assignment
	asset_names[1.1.1.1] = "Cloudflare DNS";

	# Lookups use square brackets
	print fmt("The device at 8.8.8.8 is: %s", asset_names[8.8.8.8]);

	# We can check if the key exists with 'in'
	if ( 192.168.1.100 in asset_names )
		print "We know this address!";
	else
		print "Unknown device";

	# We can even loop over all elements in key, value pairs
	for ( known_address, name in asset_names )
		{
		print fmt("Address %s is %s", known_address, name);
		}
	}
