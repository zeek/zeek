module RedefAttr;

export {
	# Here we have an indicator with just an attacker IP. Users of the library
	# can then add their own fields.
	type Indicator: record {
		attacker_ip: addr;
	} &redef;

	# You can use 'option' in order to provide config "knobs" for users.
	# These cannot be changed when the script is executing, but can via
	# redef.
	option hostname: string = "host-1";
}

# Users of the library can add fields via redef
redef record RedefAttr::Indicator += {
	ticket_num: count &default=0;
};

# They can also change the option value
redef RedefAttr::hostname = "new-host";

event zeek_init() {
 	# prints "Hostname: new-host"
  	print fmt("Hostname: %s", RedefAttr::hostname);

	# Create an instance of Indicator, with our new field
	local my_indicator: RedefAttr::Indicator = RedefAttr::Indicator(
		$attacker_ip = 192.168.1.1,
		$ticket_num = 42, # This field was added!
	);

	# prints "Found indicator: [attacker_ip=192.168.1.1, ticket_num=42]"
	print fmt("Found indicator: %s", my_indicator);
	
}
