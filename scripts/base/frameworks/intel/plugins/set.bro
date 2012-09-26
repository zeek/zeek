module Intel;

redef record Intel::Indexes += {
	hosts:   set[addr]            &default=set();
	strings: set[string, SubType] &default=set();
};

redef plugins += {
	[$index() = {

	 },
	 $match(found: Found): bool = {

	 },
	 $lookup(found: Found): set[Item] = {

	}
	]
};