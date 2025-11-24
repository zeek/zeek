type ServerHost: record {
	ip: addr;
	scanned_count: count;
	last_seen: time;
};

# Updates the scan count, as well as updating when it was last seen.
function update_scan_count(host: ServerHost)
	{
	host$scanned_count += 1;
	host$last_seen = network_time();
	}

event zeek_init()
	{
	local host: ServerHost = ServerHost(
		$ip = 192.168.1.10,
		$scanned_count = 0,
		$last_seen = network_time(),
	);

	print fmt("Before: Count=%d", host$scanned_count); # prints "Before: Count=0"

	# Pass the record into update_scan_count.
	# Zeek passes records by *reference*, so the function modifies the original.
	update_scan_count(host);
	update_scan_count(host);

	# Notice that the count was changed!
	print fmt("After: Count=%d", host$scanned_count); # prints "After: Count=2"
	}
